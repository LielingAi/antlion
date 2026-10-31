import base64
import io
import json
import zipfile

import pytest

from core.weapon_plugins.loader import PluginLoader
from experiments.dashboard import PackageUploadError, _install_weapon_package


def _zip_bytes(manifest=None, source=None, extra=None):
    manifest = manifest or {
        "id": "test.uploaded_prompt",
        "name": "Uploaded prompt",
        "version": "1.0.0",
        "api_version": 1,
        "class": "prompt",
        "entrypoint": "weapon.py:Plugin",
    }
    source = source or (
        "from core.weapon_plugins.base import PromptWeaponPlugin\n"
        "from core.weapon_plugins.models import WeaponResult\n"
        "class Plugin(PromptWeaponPlugin):\n"
        "    def render(self, context):\n"
        "        return WeaponResult.prompt('uploaded')\n"
    )
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("package/weapon.json", json.dumps(manifest))
        archive.writestr("package/weapon.py", source)
        for name, data in (extra or {}).items():
            archive.writestr(name, data)
    return base64.b64encode(buffer.getvalue()).decode()


def test_upload_installs_valid_package_without_overwrite(tmp_path):
    destination = tmp_path / "packs"
    result = _install_weapon_package("plugin.zip", _zip_bytes(), destination, reload=False)
    assert result["id"] == "test.uploaded_prompt"
    assert (destination / result["package"] / "weapon.json").is_file()
    loader = PluginLoader(str(destination))
    assert loader.get("test.uploaded_prompt") is not None

    with pytest.raises(PackageUploadError, match="已存在"):
        _install_weapon_package("plugin.zip", _zip_bytes(), destination, reload=False)


def test_upload_rejects_path_traversal(tmp_path):
    data = _zip_bytes(extra={"../escape.py": "print('no')"})
    with pytest.raises(PackageUploadError, match="traversal"):
        _install_weapon_package("plugin.zip", data, tmp_path / "packs", reload=False)
    assert not (tmp_path / "escape.py").exists()


def test_upload_rejects_missing_entrypoint(tmp_path):
    manifest = {
        "id": "test.bad", "name": "bad", "version": "1.0.0",
        "entrypoint": "missing.py:Plugin",
    }
    with pytest.raises(PackageUploadError, match="入口文件不存在"):
        _install_weapon_package("plugin.zip", _zip_bytes(manifest), tmp_path / "packs", reload=False)
    assert not (tmp_path / "packs" / "test_bad").exists()


def test_upload_rejects_invalid_python_without_installing(tmp_path):
    data = _zip_bytes(source="not valid python !!!")
    with pytest.raises(PackageUploadError, match="语法错误"):
        _install_weapon_package("plugin.zip", data, tmp_path / "packs", reload=False)
    assert not (tmp_path / "packs" / "test_uploaded_prompt").exists()
