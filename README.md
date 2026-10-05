# Maya | Esv — Servicio de validación de firmas electrónicas en PDF

Servicio HTTP (FastAPI + [pyHanko](https://github.com/MatthiasValvekens/pyHanko)) que recibe un
PDF y devuelve el resultado de validar sus firmas electrónicas: integridad, cadena de confianza,
caducidad, revocación (OCSP/CRL) y modificaciones posteriores a la firma.

---

## 1. Funcionamiento

### 1.1 Estructura

```
maya_esv/
├── app/
│   ├── main.py            # API FastAPI: endpoints, límites, códigos HTTP
│   ├── validator.py       # Lectura del PDF y validación de cada firma con pyHanko
│   ├── classification.py  # Traduce el estado de pyHanko a los estados de la API (sin dependencias)
│   ├── trust_store.py     # Certificados de confianza: SO + carpeta certs/, con caché y recarga
│   ├── models.py          # Modelos de respuesta
│   └── config.py          # Configuración por variables de entorno
├── certs/                 # Certificados adicionales (raíces, intermedias, respondedores OCSP)
├── tests/                 # Pruebas unitarias
├── Dockerfile
├── requirements.txt
└── requirements-dev.txt
```

### 1.2 Flujo de una petición

1. `POST /validate-signature` recibe el PDF (`multipart/form-data`, campo `file`).
2. Se lee por bloques con un tamaño máximo (`MAX_UPLOAD_MB`) y se comprueba la cabecera `%PDF-`.
   No se escribe nada en disco; se trabaja en memoria.
3. Se obtiene el **almacén de confianza** (ver 1.3). Es una caché: no se recarga en cada petición.
4. Se leen las firmas del PDF. Los sellos de tiempo de documento (`DocTimeStamp`) no se cuentan como firmas.
5. Cada firma se valida con pyHanko (`revocation_mode` configurable, descarga de CRL/OCSP/certificados
   intermedios por AIA si `ALLOW_FETCHING=true`) y se clasifica (ver 1.4).
6. Se calcula el estado global del documento y se responde.

### 1.3 Certificados de confianza

Se combinan dos orígenes:

| Origen | Qué se carga |
|---|---|
| **Sistema operativo** | Linux/BSD: bundle PEM del sistema (`/etc/ssl/certs/ca-certificates.crt`, `SSL_CERT_FILE`, etc.) o, si no existe, el directorio `SSL_CERT_DIR`. Windows: almacén `ROOT`. macOS: llavero de raíces del sistema. Todos se tratan como raíces de confianza. |
| **Carpeta `certs/`** | Ficheros `.crt`, `.cer`, `.pem`, `.der` (PEM o DER; uno o varios certificados por fichero; se admiten espacios en el nombre). |

Dentro de `certs/` cada certificado se trata según su naturaleza:

- **Autofirmado (raíz)** → ancla de confianza.
- **No autofirmado** (intermedias, respondedores OCSP, autoridades de validación…) → certificado
  *auxiliar*: ayuda a construir cadenas y a verificar respuestas OCSP, pero **no** es ancla de confianza.

Recarga automática: el almacén se reconstruye cuando cambia algo en `certs/` (nombre, tamaño o
fecha de modificación de algún fichero) o pasa `TRUST_REFRESH_SECONDS`. **Añadir o sustituir un
certificado no requiere reiniciar el servicio.**

> En Docker (`python:3.11-slim`) el almacén del SO es el de Debian (Mozilla). Ese almacén **no**
> incluye las raíces del DNIe, por eso se aportan en `certs/`.

### 1.4 Estados devueltos

| Estado | Significado |
|---|---|
| `SIGNED_VALID` | Firma íntegra, certificado de confianza, no revocado y sin modificaciones no permitidas. |
| `SIGNED_INVALID` | Contenido alterado, documento modificado tras firmar, firma que no cubre todo el documento, violación de DocMDP, o certificado de un emisor no confiable / cadena no verificable. |
| `SIGNED_EXPIRED` | El certificado de firma caducó y no hay sello de tiempo que lo avale. |
| `SIGNED_REVOKED` | El certificado fue revocado. |
| `NOT_SIGNED` | El PDF no contiene firmas. |
| `APP_ERROR` | Fallo al analizar una firma o error del servicio. |

Estado global (`summary_status`), por prioridad: `SIGNED_REVOKED` > `SIGNED_EXPIRED` >
`SIGNED_INVALID` > `APP_ERROR` > `SIGNED_VALID`.

Un documento con cambios posteriores *permitidos* (relleno de formularios, anotaciones) se marca
`SIGNED_VALID` con una nota en `message`. Cualquier otro cambio posterior es `SIGNED_INVALID`.

### 1.5 API

| Método y ruta | Descripción |
|---|---|
| `POST /validate-signature` | Valida un PDF (campo `file`). |
| `GET /health` | Liveness: `{"status": "ok"}`. |
| `GET /trust-store` | Resumen del almacén cargado: nº de raíces, certificados locales con su rol y caducidad, avisos. Útil para mantenimiento; **no exponer a Internet**. |
| `GET /docs` | Documentación OpenAPI interactiva. |

Códigos HTTP de `/validate-signature`:

| Código | Cuándo | Cuerpo |
|---|---|---|
| 200 | PDF procesado (con o sin firmas, válidas o no) | `ValidationResponse` |
| 400 | El fichero no es un PDF | `{"detail": ...}` |
| 413 | Supera `MAX_UPLOAD_MB` | `{"detail": ...}` |
| 422 | PDF corrupto o ilegible | `ValidationResponse` con `APP_ERROR` |
| 500 | Error interno | `ValidationResponse` con `APP_ERROR` |
| 504 | Se agotó `VALIDATION_TIMEOUT_SECONDS` (típico: CRL/OCSP inalcanzable) | `ValidationResponse` con `APP_ERROR` |

Ejemplo:

```bash
curl -F "file=@contrato.pdf" http://localhost:8000/validate-signature
```

```json
{
  "is_signed": true,
  "summary_status": "SIGNED_VALID",
  "details": [
    {
      "field_name": "Signature1",
      "status": "SIGNED_VALID",
      "signer_name": "Common Name: APELLIDO NOMBRE (AUTENTICACIÓN)",
      "message": "Firma y certificado válidos.",
      "signing_time": "2026-10-01T09:30:12+02:00",
      "certificate_valid_until": "2030-05-14T08:21:00+00:00"
    }
  ]
}
```

`signing_time` es la fecha que **declara el firmante**; no es un sello de tiempo fiable.

### 1.6 Configuración (variables de entorno)

| Variable | Por defecto | Descripción |
|---|---|---|
| `CERTS_DIR` | `<proyecto>/certs` (`/app/certs` en Docker) | Carpeta de certificados adicionales. |
| `USE_SYSTEM_CERTS` | `true` | Incluir los certificados del SO. |
| `TRUST_REFRESH_SECONDS` | `3600` | Recarga periódica del almacén (además de la detección de cambios en `certs/`). |
| `CERT_EXPIRY_WARNING_DAYS` | `30` | Antelación del aviso de caducidad de los certificados de `certs/`. |
| `REVOCATION_MODE` | `soft-fail` | `soft-fail`: si no se obtiene OCSP/CRL, no se bloquea. `hard-fail`: falla si la consulta da error. `require`: exige información de revocación. |
| `ALLOW_FETCHING` | `true` | Permitir descargar CRL/OCSP/intermedios. Requiere salida a Internet. |
| `MAX_UPLOAD_MB` | `25` | Tamaño máximo del PDF. |
| `VALIDATION_TIMEOUT_SECONDS` | `60` | Tiempo máximo de validación por petición. |
| `WEB_CONCURRENCY` | `4` | Nº de procesos de Uvicorn (cada uno tiene su propia caché de certificados). |
| `LOG_LEVEL` | `INFO` | Nivel de log. |


## 1.5 Concurrencia

La concurrencia viene de procesos, no de hilos.

### Cómo está montado

Uvicorn arranca 4 procesos (WEB_CONCURRENCY=4 en el Dockerfile). Cada proceso tiene un solo hilo con un bucle _asyncio_.
No hay un pool de hilos para validar. El único uso de hilos es la recarga del almacén de certificados, que es puntual. 

### Qué significa en la práctica

* Trabajo de CPU en paralelo: como máximo 4 validaciones a la vez, una por proceso. Es el parseo del PDF, el hash y la verificación criptográfica.
* Peticiones en curso: puede haber muchas más. Mientras una petición espera la descarga de CRL/OCSP (hasta 60 s por VALIDATION_TIMEOUT_SECONDS), ese proceso atiende otras.
* Bloqueos: mientras un proceso hace trabajo de CPU, las peticiones de ese mismo proceso esperan. Con PDFs pequeños son milisegundos. Con PDFs grandes o con muchas firmas se nota.
* Límite explícito: no he puesto ningún tope de peticiones simultáneas. El límite real es la memoria: cada petición en curso puede retener hasta 25 MB (MAX_UPLOAD_MB).
* Caché de certificados: cada proceso tiene la suya, así que hay 4 copias en memoria.

### Cómo ajustarlo

Pon WEB_CONCURRENCY cercano al número de núcleos del contenedor.
Si quieres evitar que un pico agote la memoria, añade --limit-concurrency N a Uvicorn. Las peticiones que excedan N recibirán un 503.
Para más caudal, lo más sencillo es añadir réplicas detrás de un balanceador.

Posible mejora, que no he implementado
Ejecutar cada validación en un hilo aparte con su propio bucle de eventos. Así la CPU de un PDF grande no bloquearía a las demás peticiones del mismo proceso. La ganancia de paralelismo real sería limitada por el GIL, aunque cryptography lo libera en las operaciones criptográficas. No lo he hecho porque no puedo probarlo aquí con pyhanko. Si ves bloqueos en producción, es lo primero que tocaría.


---

## 2. Puesta en marcha

### Docker

```bash
docker build -t maya_esv .
docker run -d --name maya_esv -p 8000:8000 maya_esv

# Con la carpeta certs/ montada desde el host (permite actualizar certificados sin reconstruir):
docker run -d --name maya_esv -p 8000:8000 -v "$PWD/certs:/app/certs:ro" maya_esv
```

El contenedor se ejecuta como usuario no root y trae `HEALTHCHECK` sobre `/health`.

### Local

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

### Límite de tamaño

El límite `MAX_UPLOAD_MB` protege la memoria del proceso, pero el framework ya habrá recibido el
fichero. Para un límite estricto de ancho de banda/disco, configure también el proxy inverso
(p. ej. `client_max_body_size` en nginx).

---

## 3. Mantenimiento

### 3.1 Caducidad de los certificados de `certs/`

Revise `GET /trust-store` o los logs (`WARNING certs/: ...`) periódicamente. Estado a la fecha de
esta revisión (octubre de 2026):

| Fichero | Rol | Caduca |
|---|---|---|
| `AC RAIZ DNIE 2.crt` | Raíz | 2043-09-27 |
| `ACRAIZ-SHA1.cer`, `ACRAIZ-SHA2.cer` | Raíz | 2036-02-08 |
| `AV DNIE RAIZ FNMT.cer` | Auxiliar (autoridad de validación) | **2027-03-14** |
| `OCSP Responder DNIE004/005/006.cer` | Auxiliar (respondedor OCSP) | **2027-03-14** |

Los certificados de respondedor OCSP y de la autoridad de validación se emiten con vigencia
corta (6 meses) y **hay que renovarlos** descargando los vigentes del prestador (Dirección General
de la Policía – DNIe) y sustituyendo los ficheros. Sin ellos, la validación de revocación del DNIe
puede degradar en `soft-fail` (se firma como válida sin comprobar revocación) o fallar en
`hard-fail`/`require`.

### 3.2 Añadir o sustituir un certificado

1. Copie el fichero (`.crt`, `.cer`, `.pem` o `.der`) en `certs/`.
2. Si está montada como volumen, no hace falta nada más: se detecta en la siguiente petición.
   Si la carpeta va dentro de la imagen, reconstruya la imagen y reinicie.
3. Compruebe `GET /trust-store`: el certificado debe aparecer con el rol esperado
   (`trust_root` o `auxiliary`) y sin avisos.

Importante: sólo coloque como raíz (autofirmado) lo que realmente quiera **confiar**. Una CA
intermedia no autofirmada en `certs/` no se convierte en ancla de confianza; ayuda a construir la
cadena hasta una raíz que sí lo sea.

Para ver un certificado antes de añadirlo:

```bash
openssl x509 -in fichero.cer -noout -subject -issuer -dates -ext basicConstraints
# si es DER:  openssl x509 -inform DER -in fichero.cer -noout -subject -dates
```

### 3.3 Certificados del sistema operativo

En Docker se actualizan reconstruyendo la imagen (`docker build --pull --no-cache`). Se recomienda
reconstruir al menos mensualmente para recibir los cambios del paquete `ca-certificates` y las
actualizaciones de seguridad de la imagen base.

### 3.4 Dependencias

- `pyhanko` y `pyhanko-certvalidator` están **fijadas a versiones exactas**: su API cambia entre
  versiones. Para actualizar, suba ambas a la vez, ejecute las pruebas y valide con PDFs reales
  (firmados correctamente, alterados, con certificado caducado/revocado) antes de desplegar.
- `fastapi`, `uvicorn` y `python-multipart` van con rangos: revise avisos de seguridad (por ejemplo
  con `pip-audit`) porque procesan ficheros subidos por usuarios.

### 3.5 Pruebas

```bash
pip install -r requirements-dev.txt
python -m unittest discover -s tests -v     # o: pytest
```

Cubren la clasificación de estados y el almacén de confianza. Se recomienda añadir una batería de
PDFs reales de referencia (válido, alterado, caducado, revocado, sin firma) como prueba de
integración antes de cada actualización de dependencias.

### 3.6 Diagnóstico

| Síntoma | Causa probable |
|---|---|
| Todas las firmas salen `SIGNED_INVALID` con "emisor desconocido" | Falta la raíz de la cadena en `certs/` (o `USE_SYSTEM_CERTS=false`). Revise `/trust-store`. |
| Respuestas 504 / lentitud | El servicio no alcanza los servidores CRL/OCSP (cortafuegos, proxy). Abra la salida o ajuste `VALIDATION_TIMEOUT_SECONDS`; valore `ALLOW_FETCHING=false` sólo si los PDF incluyen su información de revocación (LTV). |
| `WARNING certs/: ... CADUCADO` | Renueve el certificado (3.1). |
| `WARNING certs/: ... no contiene ningún certificado X.509 válido` | Fichero corrupto, o una clave privada/CRL en lugar de un certificado. |
| Log "El almacén de confianza está VACÍO" | No se leyó ningún certificado del SO ni de `certs/`. |
| Firma válida marcada `SIGNED_INVALID` con "modificado después de ser firmado" | El PDF se editó tras firmar (revisión con cambios no permitidos). Es el comportamiento esperado. |

Los logs no incluyen el contenido de los documentos. Los nombres de firmantes son datos personales:
no los habilite en logs de nivel DEBUG en producción sin una base legal para ello.

---

## 4. Limitaciones conocidas

- **Un certificado caducado sin sello de tiempo** se informa como `SIGNED_EXPIRED`: no se puede
  demostrar que la firma se hizo mientras era válido. Con sello de tiempo de confianza (PAdES-T/LT/LTA),
  pyHanko valida a la fecha del sellado.
- **PDF cifrados con contraseña** no se contemplan.
- **Listas de confianza de la UE (EUTL/TSL)** no se consultan; las raíces cualificadas que no estén
  en el SO deben añadirse a `certs/`.
- La verificación criptográfica de documentos muy grandes consume CPU del proceso; escale con
  `WEB_CONCURRENCY` o con más réplicas.
- La validación es **técnica**; no sustituye a un dictamen sobre el nivel de firma (simple, avanzada,
  cualificada) a efectos eIDAS.
