"""Accepted file types: detection by content (never by extension alone), normalisation at intake, and
conversion of Office documents to PDF so every released copy can carry its tracking mark.

Stored/released forms:
  PDF            -> PDF (as is)
  PNG / JPEG     -> as is; released as PNG (lossless, keeps the mark)
  GIF/BMP/WebP/TIFF -> converted to PNG at intake (first frame)
  Word/PowerPoint/Excel/OpenDocument/RTF/TXT/CSV -> converted to PDF at intake (needs LibreOffice)
"""
import io, os, shutil, subprocess, tempfile, zipfile
import numpy as np

class UnsupportedFormat(ValueError): ...
class ConversionUnavailable(RuntimeError): ...
class ConversionFailed(RuntimeError): ...

LABELS = {"pdf": "PDF", "png": "PNG image", "jpeg": "JPEG image", "gif": "GIF image", "bmp": "BMP image",
          "webp": "WebP image", "tiff": "TIFF image", "docx": "Word", "doc": "Word (older format)",
          "pptx": "PowerPoint", "ppt": "PowerPoint (older format)", "xlsx": "Excel", "xls": "Excel (older format)",
          "odt": "OpenDocument text", "odp": "OpenDocument presentation", "ods": "OpenDocument spreadsheet",
          "rtf": "Rich text", "txt": "Text", "csv": "CSV"}
IMAGES = {"png", "jpeg", "gif", "bmp", "webp", "tiff"}
ZIP_OFFICE = {"docx", "pptx", "xlsx", "odt", "odp", "ods"}
OFFICE = ZIP_OFFICE | {"doc", "ppt", "xls", "rtf", "txt", "csv"}
SUPPORTED_TEXT = "PDF, Word, PowerPoint, Excel, OpenDocument, RTF, TXT, CSV, PNG, JPEG, GIF, BMP, WebP and TIFF"
MEDIA = {"pdf": "application/pdf", "png": "image/png", "jpeg": "image/jpeg"}
MAX_PIXELS = 40_000_000
_OLE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"

def label(kind: str | None) -> str:
    return LABELS.get(kind or "", kind or "")

def media_type(kind: str) -> str:
    return MEDIA.get(kind, "application/octet-stream")

def ext_of(filename: str) -> str:
    return os.path.splitext(filename or "")[1].lower().lstrip(".")

def detect(data: bytes, filename: str = "") -> str | None:
    """Return one of LABELS' keys, or None if the content is not a supported type."""
    if not data:
        return None
    ext = ext_of(filename)
    if data[:5] == b"%PDF-": return "pdf"
    if data[:8] == b"\x89PNG\r\n\x1a\n": return "png"
    if data[:3] == b"\xff\xd8\xff": return "jpeg"
    if data[:6] in (b"GIF87a", b"GIF89a"): return "gif"
    if data[:2] == b"BM" and len(data) > 26: return "bmp"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP": return "webp"
    if data[:4] in (b"II*\x00", b"MM\x00*"): return "tiff"
    if data[:4] == b"PK\x03\x04":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                names = z.namelist()
                if "[Content_Types].xml" in names:
                    if any(n.startswith("word/") for n in names): return "docx"
                    if any(n.startswith("ppt/") for n in names): return "pptx"
                    if any(n.startswith("xl/") for n in names): return "xlsx"
                if "mimetype" in names:
                    mt = z.read("mimetype")[:100].decode("ascii", "ignore")
                    for suffix, k in (("text", "odt"), ("presentation", "odp"), ("spreadsheet", "ods")):
                        if mt.endswith("opendocument." + suffix): return k
        except Exception:
            return None
        return None
    if data[:8] == _OLE:
        for needle, k in (("WordDocument", "doc"), ("PowerPoint Document", "ppt"), ("Workbook", "xls"), ("Book", "xls")):
            if needle.encode("utf-16-le") in data[:2_000_000] or (ext == k):
                return k
        return ext if ext in ("doc", "ppt", "xls") else None
    if data.lstrip()[:5] == b"{\\rtf": return "rtf"
    if ext in ("txt", "csv"):
        try:
            data[:65536].decode("utf-8"); return ext if b"\x00" not in data[:65536] else None
        except UnicodeDecodeError:
            return None
    return None

def soffice() -> str | None:
    return shutil.which("soffice") or shutil.which("libreoffice")

def office_to_pdf(data: bytes, kind: str, timeout: int = 120) -> bytes:
    exe = soffice()
    if not exe:
        raise ConversionUnavailable(f"{label(kind)} files can't be converted because LibreOffice is not installed on this server. "
                                    "Install it (e.g. `apt install libreoffice`) or upload a PDF instead.")
    with tempfile.TemporaryDirectory(prefix="tv_conv_") as d:
        src = os.path.join(d, f"input.{kind}")
        with open(src, "wb") as f:
            f.write(data)
        env = {**os.environ, "HOME": d}
        cmd = [exe, f"-env:UserInstallation=file://{d}/profile", "--headless", "--norestore", "--nolockcheck",
               "--convert-to", "pdf", "--outdir", d, src]
        try:
            subprocess.run(cmd, capture_output=True, timeout=timeout, env=env, check=False)
        except subprocess.TimeoutExpired:
            raise ConversionFailed(f"Converting this {label(kind)} file took too long. Try a smaller file or a PDF.")
        out = os.path.join(d, "input.pdf")
        if not os.path.exists(out):
            raise ConversionFailed(f"This {label(kind)} file could not be converted. It may be damaged or password-protected.")
        with open(out, "rb") as f:
            return f.read()

def _decode_image(data: bytes):
    """-> RGB uint8 ndarray (first frame) or None."""
    try:
        from PIL import Image
        Image.MAX_IMAGE_PIXELS = MAX_PIXELS * 2
        with Image.open(io.BytesIO(data)) as im:
            if im.width * im.height > MAX_PIXELS:
                raise ConversionFailed("This image is too large (over 40 megapixels).")
            im.seek(0)
            return np.array(im.convert("RGB"))
    except ConversionFailed:
        raise
    except Exception:
        return None

def _png(rgb) -> bytes:
    from PIL import Image
    b = io.BytesIO(); Image.fromarray(rgb).save(b, "PNG"); return b.getvalue()

def _pdf_pages(pdf: bytes) -> int:
    import pymupdf
    try:
        return pymupdf.open(stream=pdf, filetype="pdf").page_count
    except Exception:
        return 0

def normalize_for_intake(data: bytes, filename: str = "") -> dict:
    """-> {stored: bytes, kind: stored kind ('pdf'|'png'|'jpeg'), source_kind: original kind}"""
    src = detect(data, filename)
    if src is None:
        raise UnsupportedFormat(f"This file type isn't supported. Supported: {SUPPORTED_TEXT}.")
    if src == "pdf":
        if _pdf_pages(data) < 1:
            raise ConversionFailed("This PDF is damaged or has no pages.")
        return {"stored": data, "kind": "pdf", "source_kind": "pdf"}
    if src in IMAGES:
        rgb = _decode_image(data)
        if rgb is None:
            raise ConversionFailed("This image is damaged or can't be read.")
        if src in ("png", "jpeg"):
            return {"stored": data, "kind": src, "source_kind": src}
        return {"stored": _png(rgb), "kind": "png", "source_kind": src}
    pdf = office_to_pdf(data, src)
    if _pdf_pages(pdf) < 1:
        raise ConversionFailed(f"This {label(src)} file converted to an empty document.")
    return {"stored": pdf, "kind": "pdf", "source_kind": src}

def embedded_images(data: bytes, kind: str, limit: int = 12) -> list:
    """Largest raster images embedded in an Office/OpenDocument zip (a leaked screenshot pasted into a deck)."""
    out = []
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            infos = [i for i in z.infolist() if ("/media/" in i.filename or i.filename.startswith("Pictures/"))
                     and i.filename.lower().rsplit(".", 1)[-1] in ("png", "jpg", "jpeg", "gif", "bmp", "tif", "tiff", "webp")
                     and 0 < i.file_size <= 40_000_000]
            for i in sorted(infos, key=lambda x: -x.file_size)[:limit]:
                try:
                    rgb = _decode_image(z.read(i))
                except ConversionFailed:
                    continue
                if rgb is not None:
                    out.append(rgb)
    except Exception:
        return []
    return out
