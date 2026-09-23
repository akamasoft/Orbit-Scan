"""Contrôles de durcissement mappés sur CIS, RGPD, ISO 27001 et PCI-DSS."""

from __future__ import annotations


def _item(check_id: str, title: str, status: str, frameworks: list[str], detail: str) -> dict:
    return {
        "id": check_id,
        "title": title,
        "status": status,
        "frameworks": frameworks,
        "detail": detail,
    }


def _sshd_value(sshd: dict, key: str) -> str:
    return (sshd.get(key) or "").strip().lower()


def evaluate(sshd: dict | None = None, policy: dict | None = None, firewall: str = "", smb: dict | None = None) -> list[dict]:
    sshd = sshd or {}
    policy = policy or {}
    checks = []

    if sshd:
        root = _sshd_value(sshd, "permitrootlogin")
        checks.append(_item(
            "ssh-root",
            "Connexion root SSH",
            "fail" if root == "yes" else "pass",
            ["CIS", "PCI-DSS", "ISO 27001"],
            "PermitRootLogin est activé." if root == "yes" else "La connexion root directe est restreinte.",
        ))
        empty = _sshd_value(sshd, "permitemptypasswords")
        checks.append(_item(
            "ssh-empty",
            "Mots de passe vides",
            "fail" if empty == "yes" else "pass",
            ["CIS", "PCI-DSS"],
            "PermitEmptyPasswords est activé." if empty == "yes" else "Les mots de passe vides sont refusés.",
        ))
        tries = _sshd_value(sshd, "maxauthtries")
        too_many = tries.isdigit() and int(tries) > 6
        checks.append(_item(
            "ssh-tries",
            "Essais d'authentification SSH",
            "fail" if too_many else "pass",
            ["CIS", "ISO 27001"],
            f"MaxAuthTries = {tries or 'défaut'}.",
        ))
        ciphers = _sshd_value(sshd, "ciphers")
        weak = [name for name in ciphers.split(",") if name in {"3des-cbc", "arcfour", "arcfour128", "arcfour256"}]
        checks.append(_item(
            "ssh-ciphers",
            "Chiffrements SSH obsolètes",
            "fail" if weak else "pass",
            ["CIS", "PCI-DSS", "ISO 27001"],
            "Présents : " + ", ".join(weak) if weak else "Aucun chiffrement arcfour ou 3DES.",
        ))
    else:
        checks.append(_item(
            "ssh-config",
            "Configuration SSH",
            "unknown",
            ["CIS"],
            "sshd -T n'a pas renvoyé de configuration.",
        ))

    minlen = policy.get("minlen") or policy.get("PASS_MIN_LEN") or ""
    if str(minlen).isdigit():
        ok = int(minlen) >= 8
        checks.append(_item(
            "password-length",
            "Longueur minimale des mots de passe",
            "pass" if ok else "fail",
            ["CIS", "PCI-DSS", "RGPD", "ISO 27001"],
            f"Minimum relevé : {minlen}.",
        ))
    else:
        checks.append(_item(
            "password-length",
            "Longueur minimale des mots de passe",
            "unknown",
            ["CIS", "PCI-DSS", "RGPD"],
            "Aucune politique de longueur lisible (login.defs ou pwquality).",
        ))

    max_days = policy.get("PASS_MAX_DAYS") or ""
    if str(max_days).isdigit():
        ok = int(max_days) <= 90
        checks.append(_item(
            "password-age",
            "Durée de vie des mots de passe",
            "pass" if ok else "fail",
            ["CIS", "PCI-DSS", "ISO 27001"],
            f"PASS_MAX_DAYS = {max_days}.",
        ))

    if firewall:
        active = firewall.strip().lower() in {"active", "enabled", "oui"}
        checks.append(_item(
            "firewall",
            "Pare-feu local",
            "pass" if active else "fail",
            ["CIS", "ISO 27001", "PCI-DSS"],
            "Un pare-feu local est actif." if active else "firewalld et ufw ne sont pas actifs.",
        ))

    if smb is not None:
        enabled = bool(smb.get("smbv1"))
        checks.append(_item(
            "smb-v1",
            "SMBv1",
            "fail" if enabled else "pass",
            ["CIS", "PCI-DSS"],
            "Le dialecte SMBv1 est accepté." if enabled else "SMBv1 n'est pas proposé.",
        ))
    return checks
