from typing import List, Dict, Any
from app.detection.normalizer import normalize_url
from app.detection.rules import analyze_url_security
from app.detection.ml import predict_url
from app.detection.domain_intel import get_domain_intelligence, evaluate_domain_risk_signal, calculate_domain_signals_score
from app.detection.tls_analyzer import inspect_tls, evaluate_tls_risk_signal
from app.detection.redirect_inspector import inspect_shortener_redirect
from app.detection.threat_intel import query_threat_intelligence
from app.detection.obfuscation import detect_obfuscation
from app.detection.brand_impersonation import detect_brand_impersonation
from app.detection.guidance import get_what_should_i_do, get_user_education_advisory

# Empirically validated risk weights determined via validation experiments
WEIGHT_RULE = 0.35
WEIGHT_ML = 0.45
WEIGHT_DOMAIN = 0.20
CONSENSUS_BONUS = 3.2


def calculate_composite_risk(raw_url: str) -> dict:
    norm = normalize_url(raw_url)
    if not norm["valid"]:
        return {
            "success": False,
            "error": norm.get("error", "Invalid URL provided."),
            "status_code": 400,
        }

    canonical_url = norm["url"]
    rule_result = analyze_url_security(canonical_url)
    ml_result = predict_url(canonical_url)
    domain_intel = get_domain_intelligence(canonical_url)
    tls_analysis = inspect_tls(canonical_url)
    threat_intel = query_threat_intelligence(canonical_url)
    obfuscation_analysis = detect_obfuscation(canonical_url)
    brand_impersonation = detect_brand_impersonation(canonical_url)

    is_trusted = rule_result.get("is_trusted", False)
    rule_score = rule_result["score"]
    ml_score = ml_result["suspicious_probability"]

    # Calculate dedicated Domain Signals Score (0-100)
    domain_signals_res = calculate_domain_signals_score(domain_intel, tls_analysis, is_trusted)
    domain_score = domain_signals_res["score"]

    # Incorporate heuristic domain & TLS indicator signals on untrusted hosts
    domain_indicators = []
    domain_reasons = []
    domain_detected = []
    tls_indicators = []
    tls_reasons = []
    tls_detected = []
    threat_indicators = []
    threat_reasons = []
    threat_detected = []
    obfuscation_indicators = []
    obfuscation_reasons = []
    obfuscation_detected = []
    brand_indicators = []
    brand_reasons = []
    brand_detected = []

    if not is_trusted:
        # Domain intelligence evaluation
        sig = evaluate_domain_risk_signal(domain_intel)
        if sig["penalty"] > 0:
            rule_score = min(rule_score + sig["penalty"], 100)
            domain_indicators = sig["indicators"]
            domain_reasons = sig["reasons"]
            domain_detected = sig["detected"]

        # TLS analysis evaluation (valid HTTPS does not clear phishing risk, but invalid/expired cert penalizes)
        tls_sig = evaluate_tls_risk_signal(tls_analysis)
        if tls_sig["penalty"] > 0:
            rule_score = min(rule_score + tls_sig["penalty"], 100)
            tls_indicators = tls_sig["indicators"]
            tls_reasons = tls_sig["reasons"]
            tls_detected = tls_sig["detected"]

        # Threat Intelligence evaluation
        if threat_intel.get("known_malicious"):
            matches = threat_intel.get("matches_count", 1)
            threat_indicators.append({
                "name": "threat_intel_match",
                "weight": 35,
                "severity": "high",
                "detail": f"Known malicious URL flagged across {matches} external threat intelligence database(s)."
            })
            threat_detected.append(f"Threat intelligence match: Reported in {matches} external database(s)")
            threat_reasons.append(f"⚠ External intelligence indicates this URL has been reported ({matches} database match(es)).")

        # Anti-obfuscation evaluation (Punycode homographs, hex IPs, encoding, nested URLs, redirect chains)
        if obfuscation_analysis.get("is_obfuscated"):
            obf_penalty = obfuscation_analysis.get("penalty", 0)
            if obf_penalty > 0:
                rule_score = min(rule_score + obf_penalty, 100)

            for tech in obfuscation_analysis.get("detected_techniques", []):
                if tech == "unicode_punycode":
                    p_info = obfuscation_analysis.get("punycode_info") or {}
                    resemble_txt = f" (Visually resembles '{p_info.get('visually_resembles')}')" if p_info.get('visually_resembles') else ""
                    obfuscation_indicators.append({
                        "name": "obfuscation_unicode_punycode",
                        "weight": 40,
                        "severity": "high",
                        "detail": f"Unicode/punycode homograph representation{resemble_txt}."
                    })
                    obfuscation_detected.append(f"Unicode/punycode domain{resemble_txt}")
                elif tech == "hex_alternative_ip":
                    ip_info = obfuscation_analysis.get("ip_obfuscation_info") or {}
                    canon = ip_info.get("canonical_ip")
                    canon_txt = f" (Canonical: {canon})" if canon else ""
                    obfuscation_indicators.append({
                        "name": "obfuscation_hex_ip",
                        "weight": 40,
                        "severity": "high",
                        "detail": f"Hexadecimal/alternative IP notation{canon_txt}."
                    })
                    obfuscation_detected.append(f"Hexadecimal/alternative IP representation{canon_txt}")
                elif tech == "url_encoding":
                    obfuscation_indicators.append({
                        "name": "obfuscation_url_encoding",
                        "weight": 30,
                        "severity": "medium",
                        "detail": "Evasive URL percent-encoding or double-encoding."
                    })
                    obfuscation_detected.append("Evasive URL percent-encoding")
                elif tech == "nested_urls":
                    n_info = obfuscation_analysis.get("nested_url_info") or {}
                    primary_nest = n_info.get("primary_nested_url") or ""
                    nest_txt = f" ({primary_nest[:60]})" if primary_nest else ""
                    obfuscation_indicators.append({
                        "name": "obfuscation_nested_url",
                        "weight": 35,
                        "severity": "high",
                        "detail": f"Concealed nested destination in parameter payload{nest_txt}."
                    })
                    obfuscation_detected.append(f"Nested URL parameter evasion{nest_txt}")
                elif tech == "multiple_redirects":
                    r_info = obfuscation_analysis.get("redirect_chain_info") or {}
                    hops = r_info.get("hop_count", 2)
                    obfuscation_indicators.append({
                        "name": "obfuscation_multiple_redirects",
                        "weight": 25,
                        "severity": "medium",
                        "detail": f"Multiple redirect chaining ({hops} hops) to evade scanning."
                    })
                    obfuscation_detected.append(f"Multiple redirect chaining ({hops} hops)")

            obfuscation_reasons.extend(obfuscation_analysis.get("reasons", []))

        # Brand Impersonation evaluation (character substitutions, misleading subdomains, typosquatting)
        if brand_impersonation.get("is_impersonation"):
            brand_penalty = brand_impersonation.get("penalty", 40)
            rule_score = min(rule_score + brand_penalty, 100)

            detected_brand = brand_impersonation.get("detected_brand", "Target Brand")
            warning_msg = brand_impersonation.get("warning_message", f"The domain is not an official {detected_brand} domain.")
            imp_types = brand_impersonation.get("impersonation_types", [])

            brand_indicators.append({
                "name": "brand_impersonation_detected",
                "weight": 40,
                "severity": "high",
                "detail": f"Unauthorized brand impersonation mimicking '{detected_brand}'. {warning_msg}"
            })
            brand_detected.append(f"Brand Impersonation: Mimicking {detected_brand}")

            if "character_substitution" in imp_types:
                sub_list = brand_impersonation.get("substitutions", [])
                sub_str = ", ".join([s.get("description", "") for s in sub_list if s.get("description")])
                brand_indicators.append({
                    "name": "brand_character_substitution",
                    "weight": 35,
                    "severity": "high",
                    "detail": f"Character substitution (leetspeak) detected: {sub_str}."
                })
                brand_detected.append("Leetspeak character substitution in domain")

            if "misleading_subdomain" in imp_types:
                brand_indicators.append({
                    "name": "brand_misleading_subdomain",
                    "weight": 40,
                    "severity": "high",
                    "detail": "Misleading subdomain disguising attacker-controlled registered domain."
                })
                brand_detected.append("Misleading subdomain brand deception")

            if "typosquatting" in imp_types:
                sim = brand_impersonation.get("similarity_score")
                sim_txt = f" ({round(sim * 100, 1)}% similarity)" if sim else ""
                brand_indicators.append({
                    "name": "brand_typosquatting_similarity",
                    "weight": 35,
                    "severity": "high",
                    "detail": f"Typosquatting similarity to '{detected_brand}'{sim_txt}."
                })
                brand_detected.append("Typosquatting brand similarity")

            brand_reasons.extend(brand_impersonation.get("reasons", []))

    # Suppress ML false positives on verified reputable domains with zero rule flags
    if is_trusted and rule_score == 0:
        effective_ml_score = min(ml_score, 10.0)
    else:
        effective_ml_score = ml_score

    # Multi-Pillar Risk Engine Synthesis:
    # 1. Reputable trusted domains with 0 rule penalties remain 0
    if is_trusted and rule_score == 0:
        final_score = 0
    else:
        # Weighted linear combination: 35% Rules + 45% ML + 20% Domain Signals
        raw_weighted = (rule_score * WEIGHT_RULE) + (effective_ml_score * WEIGHT_ML) + (domain_score * WEIGHT_DOMAIN)

        # Cross-signal consensus synergy: when >= 2 pillars indicate elevated risk
        elevated_count = sum([rule_score >= 60, effective_ml_score >= 75, domain_score >= 60])
        if elevated_count >= 2:
            raw_weighted += 3.2

        # Preserve critical ground-truth heuristics (>= 85 on untrusted hosts)
        if rule_score >= 85 and not is_trusted:
            final_score = max(round(raw_weighted), rule_score)
        else:
            final_score = round(raw_weighted)

        # Ground-truth confirmation from external threat intelligence feeds
        if threat_intel.get("known_malicious") and not is_trusted:
            final_score = max(final_score, 90)

        # Brand impersonation on untrusted host guarantees high risk classification
        if brand_impersonation.get("is_impersonation") and not is_trusted:
            final_score = max(final_score, 75)

    final_score = min(max(final_score, 0), 100)

    # Categorical Risk Level mapping (HIGH, MEDIUM, LOW)
    if final_score >= 70:
        risk_level = "HIGH"
        status = "dangerous"
        title = "Dangerous QR Destination"
        message = "High risk detected. This destination exhibits strong indicators of quishing or credential theft."
    elif final_score >= 35:
        risk_level = "MEDIUM"
        status = "suspicious"
        title = "Suspicious QR Destination"
        message = "Caution advised. This URL exhibits characteristics commonly associated with phishing campaigns."
    else:
        risk_level = "LOW"
        status = "safe"
        title = "Looks Safe"
        message = "No critical phishing indicators detected. The destination appears authentic."

    reasons: List[str] = list(rule_result["reasons"]) + domain_reasons + tls_reasons + threat_reasons + obfuscation_reasons + brand_reasons
    if effective_ml_score >= 60 and not is_trusted:
        reasons.append("The machine learning classifier identified deceptive lexical/structural URL patterns.")

    if not reasons:
        if is_trusted:
            reasons.append("Verified reputable domain structure and passing all security heuristics.")
        else:
            reasons.append("No suspicious indicators were detected during structural inspection.")

    display_ml_score = round(0 if (is_trusted and rule_score == 0) else ml_score)

    all_indicators = list(rule_result.get("indicators", [])) + domain_indicators + tls_indicators + threat_indicators + obfuscation_indicators + brand_indicators
    all_detected = list(rule_result.get("detected", [])) + domain_detected + tls_detected + threat_detected + obfuscation_detected + brand_detected

    is_shortener = rule_result.get("is_shortener", False)
    shortener_info = None
    if is_shortener:
        redirect_res = inspect_shortener_redirect(canonical_url)
        shortener_info = {
            "is_shortener": True,
            "service_name": rule_result["hostname"],
            "warning": "Destination cannot be trusted based only on the visible short URL.",
            "redirect_target": redirect_res.get("redirect_target"),
            "status_code": redirect_res.get("status_code"),
        }

    ml_detail = {
        "suspicious_probability": ml_result.get("suspicious_probability", 0.0),
        "legitimate_probability": ml_result.get("legitimate_probability", 100.0),
        "label": ml_result.get("label", "unknown"),
        "is_suspicious": ml_result.get("is_suspicious", False),
        "model_name": ml_result.get("model_name", "Gradient Boosting"),
        "features": ml_result.get("features", {}),
        "explanation": ml_result.get("explanation"),
    }

    # Actionable guidance and cybersecurity user education
    what_should_i_do = get_what_should_i_do(final_score, risk_level, is_trusted)
    user_education = get_user_education_advisory()

    return {
        "success": True,
        "url": canonical_url,
        "hostname": rule_result["hostname"],
        "score": final_score,
        "risk_level": risk_level,
        "rule_score": rule_score,
        "ml_score": display_ml_score,
        "domain_score": domain_score,
        "risk_weights": {
            "rule": WEIGHT_RULE,
            "ml": WEIGHT_ML,
            "domain": WEIGHT_DOMAIN,
        },
        "domain_signals": domain_signals_res,
        "status": status,
        "title": title,
        "message": message,
        "reasons": reasons,
        "indicators": all_indicators,
        "detected": all_detected,
        "is_trusted": is_trusted,
        "is_shortener": is_shortener,
        "is_ip": rule_result.get("is_ip", False),
        "domain_intel": domain_intel,
        "tls_analysis": tls_analysis,
        "shortener_info": shortener_info,
        "ml_detail": ml_detail,
        "threat_intel": threat_intel,
        "obfuscation_analysis": obfuscation_analysis,
        "brand_impersonation": brand_impersonation,
        "what_should_i_do": what_should_i_do,
        "user_education": user_education,
    }
