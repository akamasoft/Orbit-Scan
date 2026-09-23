"""Priorisation dynamique : une faille exploitée connue passe devant un CVSS plus haut sans exploit."""

from __future__ import annotations


def prioritize(cvss: float, kev: bool = False, exploit_known: bool = False) -> dict:
    base = float(cvss or 0)
    score = base
    if kev:
        score += 3.0
    elif exploit_known:
        score += 1.5
    if kev or score >= 9.5:
        level = "urgente"
    elif score >= 7:
        level = "haute"
    elif score >= 4:
        level = "moyenne"
    else:
        level = "faible"
    if kev and base < 9:
        reason = (
            f"Au catalogue CISA KEV : prioritaire (score {score:.1f}) "
            f"devant une faille à CVSS plus élevé sans exploit connu."
        )
    elif exploit_known:
        reason = f"Exploit public signalé dans le catalogue. Score contextuel {score:.1f} (CVSS {base:.1f})."
    else:
        reason = f"Score CVSS {base:.1f}, sans exploit connu au catalogue."
    return {"score": round(score, 1), "level": level, "reason": reason}
