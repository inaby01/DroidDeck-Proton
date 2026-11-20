"""Trusted, statically derived SoftDenchi runtime 5.0.9.0 recipe (revision 1).

Values come from a static analysis of the official bootstrap: its InstallShield
stream, the embedded MSI tables and the MSI cabinet members. Nothing here was
measured from a device prefix. Destination resolution follows standard Windows
Installer rules for a 64-bit package and is unverified on device Wine.
Only product-wide facts live here; registration IDs and device paths do not.
"""

import copy
import re

from preparation_assets import digest_json
from preparation_common import SHA256, Invalid, fields, require

HANDLER = "softdenchi-interactive"
GUID = re.compile(r"\{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\}\Z", re.ASCII)
RELATIVE = re.compile(r"(?:Program Files(?: \(x86\))?|windows)(?:/[A-Za-z0-9 ._()-]{1,96}){1,6}\Z", re.ASCII)

_FILES = (
    ("windows/syswow64/sdsys64.dll", 65536, "b8285904bf08ac06189791c3773c84fc8b688ac4fd8d2656075f5046f8171779", "x86"),
    ("Program Files (x86)/SoftDenchi/softdenchi.sdchk", 48784, "5c5d88f67638aad34b1a99c5c4f158311e699acdfb489c7f14755b9672672c40", "x86"),
    ("Program Files (x86)/SoftDenchi/HSCUD.dll", 69632, "5335f17b3ee54537e9dca765547b2314731e4eeae2c607035851689861ae3453", "x86"),
    ("Program Files (x86)/SoftDenchi/HSCUDG2.dll", 303104, "59be9a5eab85ead6fcb655d7be30dc44be1f6ba85ce81a1c098a2a72208f4046", "x86"),
    ("Program Files (x86)/SoftDenchi/HscEXD.dll", 516096, "985611fd313dfaf32cdc85280bd553beb37efd10e003e2b7c39c9d9e49c80fc8", "x86"),
    ("Program Files (x86)/SoftDenchi/HscEXDG4.dll", 434176, "98728d1fd0fb8c67227e5fa5cad05d01b8aa9dd8c99e969f6716c6c2c13d0e25", "x86"),
    ("Program Files (x86)/SoftDenchi/HscEXDG5.dll", 823296, "50fffcfbf97b94b7c8be8a1443bf674afd2c7bc710519f3e383c2a6cccce140e", "x86"),
    ("Program Files (x86)/SoftDenchi/License.txt", 22945, "fb2fa6c7f8e6a8bbea1d34570b067381a47b644c5b1e05c78eaefb4100bcd468", None),
    ("Program Files (x86)/SoftDenchi/SatX4.ocx", 400528, "06a1a6d8454a042a6a58933720e1a8927c25465c7cfac45ae8d9d7d3b0b4c953", "x86"),
    ("Program Files/SoftDenchi/SatX4.ocx", 474256, "93c707eb906c504c66d3e482e784e71fb54fa4f955d0d059693a9a0331d855e6", "x86_64"),
    ("Program Files (x86)/SoftDenchi/SdMedia.ax", 143504, "d99d3ec9e39a3e10d8de630563a29adc6e330f6643166f9a5fdea87a62e0ea7d", "x86"),
    ("Program Files (x86)/SoftDenchi/SdMediaTool.exe", 35328, "afca37c8894f692b7d725a8434994e9e192a6a32585766489e8ddd8bf3b335ce", "x86"),
    ("Program Files (x86)/SoftDenchi/SdMeter.exe", 237056, "215cc3c7046320c870cecb9b7a09243a1ea88b4a9b1295578b256434f760040f", "x86"),
    ("Program Files (x86)/SoftDenchi/SdProxy.exe", 57856, "478441227e9414188a9ca918f5e276622140a623d1349328e0e6a6dd321460d9", "x86"),
    ("Program Files (x86)/SoftDenchi/SdUsb.exe", 337920, "5ee06bad14d8c201cacff8b088a0fa3365d32365c13da684412dd2028239020a", "x86"),
    ("windows/ucharge/UCManSvc.exe", 696976, "a8b5146b5bd4abb545bcbe905044e38cb944479db089ea663b7c2fe3981aebba", "x86"),
    ("Program Files (x86)/SoftDenchi/UCManSvc.exe", 696976, "a8b5146b5bd4abb545bcbe905044e38cb944479db089ea663b7c2fe3981aebba", "x86"),
    ("Program Files (x86)/SoftDenchi/UCManSvcps.dll", 48784, "5c5d88f67638aad34b1a99c5c4f158311e699acdfb489c7f14755b9672672c40", "x86"),
    ("Program Files/SoftDenchi/UCManSvcps.dll", 9872, "f7353b7214d8f3ee9a4e287f2d46a5c8fcd3672ed4457f6ba98edf5361729f6d", "x86_64"),
    ("windows/syswow64/UCOpgDlg.dll", 414864, "fe13622f748e0e63c357eb3eeadd75de5dca11275c5cb7989d42f19bc9e5b649", "x86"),
    ("windows/system32/UCOpgDlg.dll", 507536, "8ad0da45119f9045cc2aa6e83d124af99a8e7266dd7a50e7610648ea275e36bf", "x86_64"),
    ("windows/syswow64/UCOpgDlgRes.dll", 72192, "5bdedc8d30278a18a53367c7ad526dca2676c07efc620b14c2e493fbe6250818", "x86"),
    ("windows/system32/UCOpgDlgRes.dll", 72704, "667604e407fbdbd1bc56c38e27db091852df0c9d4de809b12874f494968e3f70", "x86_64"),
    ("windows/syswow64/UCUtil32.dll", 65536, "652c269111e32e96ba3f1d5999f4c6b84a8a02df86ee178744a4d1a74c6be2b3", "x86"),
    ("windows/syswow64/UCUtil38.dll", 65536, "c8d13c2cb049d78c8a74971eb96fb62459187e77c7a7129559a299e970ec98f2", "x86"),
    ("windows/syswow64/UCUtil41.dll", 73728, "f04c9feb79378e06f4f4aadcb0a5099cae28878e80e7d90045c5d7d182f8e332", "x86"),
    ("windows/syswow64/UCUtil50.dll", 143872, "6fdf5e1901c4bad1058fd6fabfbb907a4d3292b8ccece8416686d40b1a18998d", "x86"),
    ("windows/system32/UCUtil50.dll", 177152, "ca13bb2790bf26c4ba1c3f734e28e424ddf7a0297be80916010439ba30424dc8", "x86_64"),
    ("Program Files (x86)/SoftDenchi/UCX.ocx", 138752, "606f7d54262f837d48f4ea14c88d0a18752fc35c130779f2d4817092557726fe", "x86"),
    ("Program Files/SoftDenchi/UCX.ocx", 165376, "77ad9d418d5cc8e89fcf9c347faf49e7d9ebf8d8589c6278bdf4358d405e59da", "x86_64"),
    ("Program Files (x86)/SoftDenchi/html/base.css", 1300, "87a4b9c2100d9bcce369317b2520fc8ca8fedbc85b4540fdc2205d8169438788", None),
    ("Program Files (x86)/SoftDenchi/html/NoDenchi.avi", 94720, "b6dee2a5bc60d3cd8ae31d11f7145c8e5e353c8b9cf3f215957dade23bd028e0", None),
    ("Program Files (x86)/SoftDenchi/html/pccode.htm", 2832, "dc6e7ae5d575eaded576948e50bd81ba67197b96d5f7da7f8287e3897685db4e", None),
    ("Program Files (x86)/SoftDenchi/html/sd_broken.htm", 1556, "f4c2a98ffc301b917f5d9ffa0e951c768b087dd4c1524c703905e56f25f97b77", None),
    ("Program Files (x86)/SoftDenchi/html/sd_direct.htm", 1209, "4f891ab0e7c84f39a115567f7eafdfbd7c47f9b6eb3b475a6af350350ad2bc3c", None),
    ("Program Files (x86)/SoftDenchi/html/sd_empty_cancel.htm", 1363, "a8b93a19960ceeba6b9ee10b20ef85ae87a3143744afcdce345984c5829e78e4", None),
    ("Program Files (x86)/SoftDenchi/html/sd_empty_try.htm", 1491, "fe73f70cf5bec7649a51494b39231624fdab3f382111392b111d430a1fc5b809", None),
    ("Program Files (x86)/SoftDenchi/html/sd_enough.htm", 1460, "2b8b3d75658a3ec96fcdd0c29fbe0d81bad7cdf10711aecb2d806c8c6fd8c3fb", None),
    ("Program Files (x86)/SoftDenchi/html/sd_initial.htm", 1530, "aa409799be88aa380c552f48e58f98e59bc91ec494d6feff7909087faec8c227", None),
    ("Program Files (x86)/SoftDenchi/html/sd_little.htm", 1460, "71f9713bec14b167b93775c222843416a1dc79847c5ae6675d2e11fbbbf3d5a5", None),
    ("Program Files (x86)/SoftDenchi/html/sd_no_runtime.htm", 1131, "d2da44540078dabd094ef442cc7858bdf1eae07fc75b82bd78a4eaad4e7b7bb7", None),
    ("Program Files (x86)/SoftDenchi/html/sd_trial.htm", 1493, "35147702e5343ede958c65b64af1bec0ac091117dfbdc966499fb26607e57053", None),
    ("Program Files (x86)/SoftDenchi/html/sd_unlimited.htm", 1182, "9ba830c85a9194be1ec4f39f255bee7222410382c97743ae493ce6bfd646e8a4", None),
)

# MSI Class table rows. The view follows the component bitness, as the patched
# Wine MSI class registration does; x86 rows use the 32-bit (Wow6432Node) view.
_CLASSES = (
    ("{063FA84A-F20A-46C2-B67F-70E69DF4A7AB}", "InprocServer32", "x86", "Program Files (x86)/SoftDenchi/SatX4.ocx"),
    ("{063FA84A-F20A-46C2-B67F-70E69DF4A7AB}", "InprocServer32", "x64", "Program Files/SoftDenchi/SatX4.ocx"),
    ("{0D933188-6784-43CB-BF91-C6AB019C3E57}", "InprocServer32", "x86", "Program Files (x86)/SoftDenchi/SatX4.ocx"),
    ("{0D933188-6784-43CB-BF91-C6AB019C3E57}", "InprocServer32", "x64", "Program Files/SoftDenchi/SatX4.ocx"),
    ("{18832FDB-D9D2-40C8-9051-6400E0053F4C}", "InprocServer32", "x86", "Program Files (x86)/SoftDenchi/SdMedia.ax"),
    ("{6CF50DB3-5270-4E8B-A9C0-5C524815062C}", "InprocServer32", "x86", "Program Files (x86)/SoftDenchi/SatX4.ocx"),
    ("{6CF50DB3-5270-4E8B-A9C0-5C524815062C}", "InprocServer32", "x64", "Program Files/SoftDenchi/SatX4.ocx"),
    ("{7E215A76-D33A-42A5-9B5C-FFDCF5896112}", "InprocServer32", "x86", "Program Files (x86)/SoftDenchi/UCX.ocx"),
    ("{7E215A76-D33A-42A5-9B5C-FFDCF5896112}", "InprocServer32", "x64", "Program Files/SoftDenchi/UCX.ocx"),
    ("{973558CA-B388-11D3-AEF6-0040264002C6}", "LocalServer32", "x86", "Program Files (x86)/SoftDenchi/UCManSvc.exe"),
    ("{A4B5C240-193B-4382-8837-1E9F83E94D6B}", "InprocServer32", "x86", "Program Files (x86)/SoftDenchi/UCX.ocx"),
    ("{A4B5C240-193B-4382-8837-1E9F83E94D6B}", "InprocServer32", "x64", "Program Files/SoftDenchi/UCX.ocx"),
    ("{FE02AB79-9738-4040-B892-6B9495ACE7B6}", "InprocServer32", "x86", "Program Files (x86)/SoftDenchi/SatX4.ocx"),
    ("{FE02AB79-9738-4040-B892-6B9495ACE7B6}", "InprocServer32", "x64", "Program Files/SoftDenchi/SatX4.ocx"),
    ("{973558C7-B388-11D3-AEF6-0040264002C6}", "InprocServer32", "x86", "Program Files (x86)/SoftDenchi/UCManSvcps.dll"),
)

_RECIPE = {
    "handler": HANDLER,
    "revision": 1,
    "bootstrap": {"filename": "sdrt5090_x64.exe", "size": 33825048, "pe_machine": "x86",
                  "sha256": "b29f5e2a374bbfd07d723563989655ea9efec2c8878c0ef479bbf20ff075fa89"},
    "product": {"product_code": "{63A3DBCF-FB40-4398-9AE5-94EE6206CE12}", "version": "5.0.9.0",
                "upgrade_code": "{7986EAFC-694C-42CD-84FB-EB3900E89AF0}",
                "marker_key": "Software\\Wow6432Node\\Paltiosoft\\UCharge", "marker_value": "sdrt", "marker_data": "5090"},
    "service": {"name": "UCManSvc", "type": 0x110, "start": 2, "image": "Program Files (x86)/SoftDenchi/UCManSvc.exe"},
    "files": [list(item) for item in _FILES],
    "classes": [list(item) for item in _CLASSES],
    "trace_directories": ["Program Files (x86)/SoftDenchi", "Program Files/SoftDenchi", "windows/ucharge"],
}


def softdenchi_recipe():
    return copy.deepcopy(_RECIPE)


def validate_recipe(recipe):
    """Shape checks for the trusted recipe and for synthetic test recipes."""
    fields(recipe, ("handler", "revision", "bootstrap", "product", "service", "files", "classes", "trace_directories"))
    require(recipe["handler"] == HANDLER and type(recipe["revision"]) is int and recipe["revision"] >= 1, "unsupported recipe")
    boot = recipe["bootstrap"]
    fields(boot, ("filename", "size", "pe_machine", "sha256"))
    require(type(boot["filename"]) is str and re.fullmatch(r"[A-Za-z0-9_.-]{1,64}\.exe", boot["filename"], re.ASCII),
            "invalid bootstrap filename")
    require(type(boot["size"]) is int and boot["size"] > 0 and boot["pe_machine"] == "x86" and
            type(boot["sha256"]) is str and SHA256.fullmatch(boot["sha256"]), "invalid bootstrap identity")
    product = recipe["product"]
    fields(product, ("product_code", "version", "upgrade_code", "marker_key", "marker_value", "marker_data"))
    require(all(type(product[k]) is str and GUID.fullmatch(product[k]) for k in ("product_code", "upgrade_code")), "invalid product GUID")
    require(all(type(product[k]) is str and 0 < len(product[k]) <= 256 for k in ("version", "marker_key", "marker_value", "marker_data")),
            "invalid product marker")
    service = recipe["service"]
    fields(service, ("name", "type", "start", "image"))
    require(type(service["name"]) is str and re.fullmatch(r"[A-Za-z0-9_]{1,64}", service["name"], re.ASCII) and
            type(service["type"]) is int and type(service["start"]) is int, "invalid service expectation")
    files = recipe["files"]
    require(type(files) is list and 0 < len(files) <= 256, "invalid file list")
    seen = set()
    for item in files:
        require(type(item) is list and len(item) == 4, "invalid file entry")
        path, size, digest, machine = item
        require(type(path) is str and RELATIVE.fullmatch(path) and ".." not in path.split("/"), "invalid file destination")
        require(path.casefold() not in seen, "duplicate file destination")
        seen.add(path.casefold())
        require(type(size) is int and 0 < size <= 64 * 1024**2 and type(digest) is str and SHA256.fullmatch(digest) and
                machine in (None, "x86", "x86_64"), "invalid file expectation")
    require(service["image"].casefold() in seen, "service image must be an expected file")
    classes = recipe["classes"]
    require(type(classes) is list and 0 < len(classes) <= 256, "invalid class list")
    for item in classes:
        require(type(item) is list and len(item) == 4, "invalid class entry")
        clsid, context, view, server = item
        require(type(clsid) is str and GUID.fullmatch(clsid) and context in ("InprocServer32", "LocalServer32") and
                view in ("x86", "x64") and type(server) is str and server.casefold() in seen, "invalid class expectation")
    directories = recipe["trace_directories"]
    require(type(directories) is list and 0 < len(directories) <= 16 and
            all(type(d) is str and RELATIVE.fullmatch(d) for d in directories), "invalid trace directories")
    return recipe


# Silent launch of the recipe bootstrap (one-pass preparation only). The bootstrap is an
# InstallShield Basic MSI setup.exe (Setup.ini ScriptDriven=0); "/s" with "/v<msiexec option>"
# is its documented silent form, and /v may be repeated. REBOOT=ReallySuppress keeps the MSI
# (ScheduleReboot under ISSCHEDULEREBOOT) from restarting. No argument contains a space, so
# nothing depends on quoting through Wine. Bound to the exact bootstrap; not part of the
# recipe digest, so records of interactive installations stay comparable.
SILENT_LAUNCH = {"bootstrap_sha256": _RECIPE["bootstrap"]["sha256"],
                 "arguments": ["/s", "/v/qn", "/vREBOOT=ReallySuppress"]}


def silent_arguments(recipe, launch=None):
    """The pinned silent arguments for this recipe's bootstrap, or refusal."""
    validate_recipe(recipe)
    launch = SILENT_LAUNCH if launch is None else launch
    fields(launch, ("bootstrap_sha256", "arguments"))
    arguments = launch["arguments"]
    require(launch["bootstrap_sha256"] == recipe["bootstrap"]["sha256"], "silent launch not defined for this bootstrap")
    require(type(arguments) is list and 0 < len(arguments) <= 8 and
            all(type(a) is str and re.fullmatch(r"/[A-Za-z0-9/=_.-]{1,64}", a, re.ASCII) for a in arguments),
            "invalid silent arguments")
    return list(arguments)


def recipe_digest(recipe):
    return digest_json(validate_recipe(recipe))


def bind_asset(recipe, spec, measured):
    """A manifest entry runs under this handler only if it is the recipe's exact bootstrap."""
    validate_recipe(recipe)
    boot = recipe["bootstrap"]
    try:
        require(spec["filename"] == boot["filename"] and spec["expected_sha256"] == boot["sha256"] and
                spec["expected_size"] == boot["size"] and spec["format"] == "pe" and spec["pe_machine"] == boot["pe_machine"],
                "asset declaration differs from the trusted recipe bootstrap")
        require(measured is not None and measured["sha256"] == boot["sha256"] and measured["size"] == boot["size"] and
                measured["pe_machine"] == boot["pe_machine"], "measured asset differs from the trusted recipe bootstrap")
    except KeyError as error:
        raise Invalid("incomplete asset declaration") from error
    return {"recipe_revision": recipe["revision"], "recipe_digest": recipe_digest(recipe), "bootstrap_sha256": boot["sha256"]}
