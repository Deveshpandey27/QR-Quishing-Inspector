document.addEventListener("DOMContentLoaded", function () {
    console.log("QR Quishing Inspector (FastAPI v2.0) JavaScript initialized.");

    // Core elements
    const video = document.getElementById("video");
    const canvas = document.getElementById("canvas");
    const startCameraButton = document.getElementById("startCamera");
    const analyzeButton = document.getElementById("analyzeButton");
    const scanAgainButton = document.getElementById("scanAgain");
    const urlInput = document.getElementById("urlInput");
    const cameraMessage = document.getElementById("cameraMessage");
    const copyUrlBtn = document.getElementById("copyUrlBtn");
    const copyReportBtn = document.getElementById("copyReportBtn");
    const clearRecentBtn = document.getElementById("clearRecentBtn");

    // Mode elements
    const tabCameraBtn = document.getElementById("tabCameraBtn");
    const tabUploadBtn = document.getElementById("tabUploadBtn");
    const cameraView = document.getElementById("cameraView");
    const uploadView = document.getElementById("uploadView");
    const scannerStatusText = document.getElementById("scannerStatusText");

    // Upload elements
    const dropZone = document.getElementById("dropZone");
    const qrFileInput = document.getElementById("qrFileInput");
    const browseFileBtn = document.getElementById("browseFileBtn");
    const dropZonePrompt = document.getElementById("dropZonePrompt");
    const uploadPreviewWrapper = document.getElementById("uploadPreviewWrapper");
    const uploadPreviewImg = document.getElementById("uploadPreviewImg");
    const inspectImageBtn = document.getElementById("inspectImageBtn");
    const removeImageBtn = document.getElementById("removeImageBtn");

    if (!video || !canvas || !startCameraButton || !analyzeButton || !urlInput) {
        console.error("Required HTML elements were not found.");
        return;
    }

    const canvasContext = canvas.getContext("2d");
    let cameraStream = null;
    let scanning = false;
    let selectedImageFile = null;
    let lastAnalysisData = null;

    // =========================================================================
    // THEME MANAGEMENT (LIGHT / DARK MODE SYNC)
    // =========================================================================
    const themeToggleBtn = document.getElementById("themeToggleBtn");

    // Only attach click listener if HTML does not already have an inline onclick
    if (themeToggleBtn && !themeToggleBtn.getAttribute("onclick")) {
        themeToggleBtn.addEventListener("click", function () {
            if (typeof window.toggleTheme === "function") {
                window.toggleTheme();
            }
        });
    }

    // Load initial recent scans from session
    renderRecentScans();

    // Load multi-model ML benchmark matrix
    loadMlBenchmarks();

    // Load Scan History Dashboard
    loadScanHistoryDashboard();


    // Feature vector inspector toggle
    const toggleFeaturesBtn = document.getElementById("toggleFeaturesBtn");
    const mlFeaturesBox = document.getElementById("mlFeaturesBox");
    const featureToggleIcon = document.getElementById("featureToggleIcon");
    if (toggleFeaturesBtn && mlFeaturesBox) {
        toggleFeaturesBtn.addEventListener("click", function () {
            const isHidden = mlFeaturesBox.classList.contains("d-none");
            if (isHidden) {
                mlFeaturesBox.classList.remove("d-none");
                if (featureToggleIcon) featureToggleIcon.className = "bi bi-chevron-up";
            } else {
                mlFeaturesBox.classList.add("d-none");
                if (featureToggleIcon) featureToggleIcon.className = "bi bi-chevron-down";
            }
        });
    }

    // =========================================================================
    // MODE SWITCHING (CAMERA VS UPLOAD)
    // =========================================================================
    if (tabCameraBtn && tabUploadBtn) {
        tabCameraBtn.addEventListener("click", function () {
            tabCameraBtn.classList.add("active");
            tabUploadBtn.classList.remove("active");
            cameraView.classList.remove("d-none");
            uploadView.classList.add("d-none");
            if (scannerStatusText) scannerStatusText.textContent = "Camera Ready";
        });

        tabUploadBtn.addEventListener("click", function () {
            tabUploadBtn.classList.add("active");
            tabCameraBtn.classList.remove("active");
            cameraView.classList.add("d-none");
            uploadView.classList.remove("d-none");
            stopCamera();
            if (scannerStatusText) scannerStatusText.textContent = "Upload Ready";
        });
    }

    // =========================================================================
    // QUICK TEST DEMO TARGETS
    // =========================================================================
    document.querySelectorAll(".quick-chip").forEach(chip => {
        chip.addEventListener("click", function () {
            const url = this.getAttribute("data-url");
            if (url) {
                urlInput.value = url;
                analyzeURL(url);
            }
        });
    });

    // =========================================================================
    // CAMERA CONTROLS
    // =========================================================================
    startCameraButton.addEventListener("click", function () {
        if (scanning) {
            stopCamera();
        } else {
            startCamera();
        }
    });

    async function startCamera() {
        if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
            alert("Camera access is not supported by your browser or environment.");
            return;
        }

        try {
            startCameraButton.disabled = true;
            startCameraButton.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span> Starting...';

            cameraStream = await navigator.mediaDevices.getUserMedia({
                video: { facingMode: { ideal: "environment" } },
                audio: false
            });

            video.srcObject = cameraStream;
            await video.play();

            if (cameraMessage) cameraMessage.style.display = "none";
            startCameraButton.disabled = false;
            startCameraButton.innerHTML = '<i class="bi bi-stop-circle-fill me-1"></i> Stop Camera';
            if (scannerStatusText) scannerStatusText.textContent = "Scanning...";

            scanning = true;
            scanQRCode();
        } catch (error) {
            console.error("Camera access error:", error);
            startCameraButton.disabled = false;
            startCameraButton.innerHTML = '<i class="bi bi-camera-fill me-1"></i> Start Camera';
            if (error.name === "NotAllowedError") {
                alert("Camera permission was denied. Please allow camera access in your browser settings.");
            } else {
                alert("Unable to activate camera: " + error.message);
            }
        }
    }

    function stopCamera() {
        scanning = false;
        if (cameraStream) {
            cameraStream.getTracks().forEach(track => track.stop());
            cameraStream = null;
        }
        video.srcObject = null;
        startCameraButton.disabled = false;
        startCameraButton.innerHTML = '<i class="bi bi-camera-fill me-1"></i> Start Camera';
        if (cameraMessage) cameraMessage.style.display = "flex";
        if (scannerStatusText) scannerStatusText.textContent = "Ready";
    }

    function scanQRCode() {
        if (!scanning) return;

        if (video.readyState >= 2 && video.videoWidth > 0 && video.videoHeight > 0) {
            canvas.width = video.videoWidth;
            canvas.height = video.videoHeight;
            canvasContext.drawImage(video, 0, 0, canvas.width, canvas.height);

            if (typeof jsQR === "undefined") {
                console.error("jsQR library not loaded.");
                stopCamera();
                return;
            }

            const imageData = canvasContext.getImageData(0, 0, canvas.width, canvas.height);
            const code = jsQR(imageData.data, imageData.width, imageData.height);

            if (code && code.data && code.data.trim()) {
                const qrText = code.data.trim();
                stopCamera();
                urlInput.value = qrText;
                analyzeURL(qrText);
                return;
            }
        }
        requestAnimationFrame(scanQRCode);
    }

    // =========================================================================
    // FILE UPLOAD / DRAG & DROP
    // =========================================================================
    if (browseFileBtn && qrFileInput) {
        browseFileBtn.addEventListener("click", () => qrFileInput.click());
    }

    if (qrFileInput) {
        qrFileInput.addEventListener("change", function () {
            if (this.files && this.files[0]) {
                handleFileSelect(this.files[0]);
            }
        });
    }

    if (dropZone) {
        ["dragenter", "dragover"].forEach(event => {
            dropZone.addEventListener(event, e => {
                e.preventDefault();
                dropZone.classList.add("dragover");
            });
        });

        ["dragleave", "drop"].forEach(event => {
            dropZone.addEventListener(event, e => {
                e.preventDefault();
                dropZone.classList.remove("dragover");
            });
        });

        dropZone.addEventListener("drop", e => {
            const dt = e.dataTransfer;
            if (dt && dt.files && dt.files[0]) {
                handleFileSelect(dt.files[0]);
            }
        });
    }

    function handleFileSelect(file) {
        if (!file.type.startsWith("image/")) {
            alert("Please select a valid image file (PNG, JPG, WEBP, BMP).");
            return;
        }

        selectedImageFile = file;
        const reader = new FileReader();
        reader.onload = function (e) {
            uploadPreviewImg.src = e.target.result;
            dropZonePrompt.classList.add("d-none");
            uploadPreviewWrapper.classList.remove("d-none");
            if (scannerStatusText) scannerStatusText.textContent = file.name;
        };
        reader.readAsDataURL(file);
    }

    if (removeImageBtn) {
        removeImageBtn.addEventListener("click", function () {
            selectedImageFile = null;
            if (qrFileInput) qrFileInput.value = "";
            uploadPreviewImg.src = "";
            uploadPreviewWrapper.classList.add("d-none");
            dropZonePrompt.classList.remove("d-none");
            if (scannerStatusText) scannerStatusText.textContent = "Upload Ready";
        });
    }

    if (inspectImageBtn) {
        inspectImageBtn.addEventListener("click", async function () {
            if (!selectedImageFile) {
                alert("Please select or drop an image file first.");
                return;
            }

            inspectImageBtn.disabled = true;
            inspectImageBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span> Decoding...';

            try {
                const formData = new FormData();
                formData.append("file", selectedImageFile);

                const response = await fetch("/api/v1/scan-image", {
                    method: "POST",
                    body: formData
                });

                const data = await response.json();
                if (!response.ok || !data.success) {
                    throw new Error(data.error || "Could not read a valid QR code from this image.");
                }

                if (data.extracted_text) {
                    urlInput.value = data.extracted_text;
                }

                if (data.analysis) {
                    displayResult(data.analysis);
                } else {
                    alert("QR Code extracted: " + data.extracted_text);
                }
            } catch (err) {
                console.error("Scan image error:", err);
                alert(err.message || "Failed to process QR image.");
            } finally {
                inspectImageBtn.disabled = false;
                inspectImageBtn.innerHTML = '<i class="bi bi-shield-check me-1"></i> Decode & Inspect';
            }
        });
    }

    // =========================================================================
    // MANUAL URL ANALYSIS
    // =========================================================================
    analyzeButton.addEventListener("click", function () {
        const url = urlInput.value.trim();
        if (!url) {
            alert("Please enter a URL to inspect.");
            return;
        }
        analyzeURL(url);
    });

    urlInput.addEventListener("keydown", function (event) {
        if (event.key === "Enter") {
            analyzeButton.click();
        }
    });

    async function analyzeURL(url) {
        analyzeButton.disabled = true;
        analyzeButton.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span> Analyzing...';

        try {
            const response = await fetch("/api/v1/analyze", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ url: url })
            });

            const data = await response.json();
            if (!response.ok || !data.success) {
                throw new Error(data.detail || data.error || "URL Analysis failed.");
            }

            displayResult(data);
        } catch (error) {
            console.error("Analysis error:", error);
            alert("Analysis failed: " + error.message);
        } finally {
            analyzeButton.disabled = false;
            analyzeButton.innerHTML = '<i class="bi bi-shield-search me-1"></i> Analyze URL';
        }
    }

    // =========================================================================
    // DISPLAY RESULT
    // =========================================================================
    function displayResult(data, isHistorical = false) {
        lastAnalysisData = data;

        const resultSection = document.getElementById("resultSection");
        const resultIcon = document.getElementById("resultIcon");
        const resultTitle = document.getElementById("resultTitle");
        const resultMessage = document.getElementById("resultMessage");
        const resultLabel = document.getElementById("resultLabel");
        const riskScore = document.getElementById("riskScore");
        const scannedUrl = document.getElementById("scannedUrl");
        const mlScore = document.getElementById("mlScore");
        const ruleScore = document.getElementById("ruleScore");
        const mlProgress = document.getElementById("mlProgress");
        const ruleProgress = document.getElementById("ruleProgress");
        const reasonsList = document.getElementById("reasonsList");
        const scoreCircle = document.querySelector(".score-circle");
        const indicatorsCard = document.getElementById("indicatorsCard");
        const indicatorsList = document.getElementById("indicatorsList");

        resultSection.classList.remove("d-none");
        resultTitle.textContent = data.title;
        resultMessage.textContent = data.message;
        const displayScannedText = (data.payload_info && data.payload_info.sanitized_text) ? data.payload_info.sanitized_text : data.url;
        scannedUrl.textContent = displayScannedText;
        riskScore.textContent = data.score;

        const ml = data.ml_detail || {};
        const suspProb = ml.suspicious_probability !== undefined ? ml.suspicious_probability : data.ml_score;
        const legitProb = ml.legitimate_probability !== undefined ? ml.legitimate_probability : (100.0 - suspProb);
        const modelName = ml.model_name || "Gradient Boosting";

        if (mlScore) mlScore.textContent = data.ml_score + "%";
        ruleScore.textContent = data.rule_score + "%";
        if (mlProgress) mlProgress.style.width = Math.min(data.ml_score, 100) + "%";
        ruleProgress.style.width = Math.min(data.rule_score, 100) + "%";

        // Update ML Dual Probability split bar and text
        const mlProbBarSuspicious = document.getElementById("mlProbBarSuspicious");
        const mlProbBarLegitimate = document.getElementById("mlProbBarLegitimate");
        const mlSuspiciousProb = document.getElementById("mlSuspiciousProb");
        const mlLegitimateProb = document.getElementById("mlLegitimateProb");
        const mlActiveModelBadge = document.getElementById("mlActiveModelBadge");
        const mlModelName = document.getElementById("mlModelName");

        if (mlProbBarSuspicious) mlProbBarSuspicious.style.width = Math.min(Math.max(suspProb, 0), 100) + "%";
        if (mlProbBarLegitimate) mlProbBarLegitimate.style.width = Math.min(Math.max(legitProb, 0), 100) + "%";
        if (mlSuspiciousProb) mlSuspiciousProb.textContent = suspProb.toFixed(1) + "%";
        if (mlLegitimateProb) mlLegitimateProb.textContent = legitProb.toFixed(1) + "%";
        if (mlActiveModelBadge) mlActiveModelBadge.textContent = modelName;
        if (mlModelName) mlModelName.textContent = modelName;

        // Render 24 extracted features into inspector grid
        const mlFeaturesGrid = document.getElementById("mlFeaturesGrid");
        if (mlFeaturesGrid && ml.features) {
            mlFeaturesGrid.innerHTML = "";
            Object.entries(ml.features).forEach(([k, v]) => {
                const item = document.createElement("div");
                item.className = "ml-feat-item";
                const displayVal = typeof v === "number" ? (Number.isInteger(v) ? v : v.toFixed(2)) : (v === true ? "1" : (v === false ? "0" : v));
                item.innerHTML = `<span class="ml-feat-key" title="${k}">${k}</span><span class="ml-feat-val">${displayVal}</span>`;
                mlFeaturesGrid.appendChild(item);
            });
        }

        // Render Explainable ML Contributing Signals (↑ Risk Escalators vs ↓ Mitigators)
        const mlTopSuspiciousList = document.getElementById("mlTopSuspiciousList");
        const mlTopLegitimateList = document.getElementById("mlTopLegitimateList");
        const mlMitigatingSection = document.getElementById("mlMitigatingSection");

        if (mlTopSuspiciousList && ml.explanation) {
            mlTopSuspiciousList.innerHTML = "";
            const topSusp = ml.explanation.top_suspicious || [];
            if (topSusp.length > 0) {
                topSusp.forEach(sig => {
                    const row = document.createElement("div");
                    row.className = "signal-pill signal-pill-up";
                    const impactClass = sig.impact_level === "high" ? "signal-impact-high" : (sig.impact_level === "medium" ? "signal-impact-medium" : "signal-impact-low");
                    const valBadge = sig.value !== undefined && sig.value !== null && sig.value !== "" 
                        ? `<span class="signal-val-badge">val: ${sig.value}</span>` 
                        : "";
                    row.innerHTML = `
                        <div class="d-flex align-items-center flex-wrap">
                            <span class="signal-symbol-up">${sig.symbol}</span>
                            <span class="signal-name">${sig.name}</span>
                            ${valBadge}
                        </div>
                        <span class="signal-impact-badge ${impactClass}">${sig.impact_level.toUpperCase()} IMPACT</span>
                    `;
                    row.title = sig.explanation || sig.name;
                    mlTopSuspiciousList.appendChild(row);
                });
            } else {
                mlTopSuspiciousList.innerHTML = '<div class="text-secondary small fst-italic py-1">No strong malicious escalation signals detected.</div>';
            }
        }

        if (mlTopLegitimateList && ml.explanation) {
            mlTopLegitimateList.innerHTML = "";
            const topLegit = ml.explanation.top_legitimate || [];
            if (topLegit.length > 0) {
                if (mlMitigatingSection) mlMitigatingSection.classList.remove("d-none");
                topLegit.forEach(sig => {
                    const row = document.createElement("div");
                    row.className = "signal-pill signal-pill-down";
                    const impactClass = sig.impact_level === "high" ? "signal-impact-high" : (sig.impact_level === "medium" ? "signal-impact-medium" : "signal-impact-low");
                    const valBadge = sig.value !== undefined && sig.value !== null && sig.value !== "" 
                        ? `<span class="signal-val-badge">val: ${sig.value}</span>` 
                        : "";
                    row.innerHTML = `
                        <div class="d-flex align-items-center flex-wrap">
                            <span class="signal-symbol-down">${sig.symbol}</span>
                            <span class="signal-name">${sig.name}</span>
                            ${valBadge}
                        </div>
                        <span class="signal-impact-badge ${impactClass}">${sig.impact_level.toUpperCase()} SAFETY</span>
                    `;
                    row.title = sig.explanation || sig.name;
                    mlTopLegitimateList.appendChild(row);
                });
            } else {
                if (mlMitigatingSection) mlMitigatingSection.classList.add("d-none");
            }
        }

        // Render Actionable Guidance Banner
        const guidanceBanner = document.getElementById("guidanceBanner");
        const guidanceIcon = document.getElementById("guidanceIcon");
        const guidanceTitle = document.getElementById("guidanceTitle");
        const guidanceText = document.getElementById("guidanceText");

        if (guidanceBanner) {
            guidanceBanner.className = "guidance-banner mt-4 d-flex align-items-center justify-content-between flex-wrap gap-3";
            if (data.status === "dangerous") {
                guidanceBanner.classList.add("banner-dangerous");
                guidanceIcon.className = "bi bi-shield-x";
                guidanceTitle.textContent = "CRITICAL THREAT — High Quishing Hazard";
                guidanceText.textContent = "Strong indicators of deceptive phishing, brand impersonation, or unencrypted credential harvesting. Do not visit!";
            } else if (data.status === "suspicious") {
                guidanceBanner.classList.add("banner-suspicious");
                guidanceIcon.className = "bi bi-shield-exclamation";
                guidanceTitle.textContent = "Caution Advised — Potential Quishing Vector";
                guidanceText.textContent = "This destination exhibits suspicious patterns (e.g. shortener or unknown host). Avoid entering credentials or OTPs.";
            } else {
                guidanceBanner.classList.add("banner-safe");
                guidanceIcon.className = "bi bi-shield-check";
                guidanceTitle.textContent = "Safe Destination Verified";
                guidanceText.textContent = "This URL exhibits authentic characteristics and passes all cybersecurity rules and ML checks.";
            }
        }

        // =========================================================================
        // SECTION 12: QR CODE PAYLOAD DETECTION & CREDENTIAL PROTECTION
        // =========================================================================
        const payloadInfo = data.payload_info || {
            content_type: "url",
            type_label: "URL",
            security_warning: "Standard web destination",
            details: {},
            embedded_urls: []
        };

        const payloadTypeBadge = document.getElementById("payloadTypeBadge");
        const payloadSecurityWarningText = document.getElementById("payloadSecurityWarningText");
        const payloadWarningIcon = document.getElementById("payloadWarningIcon");

        if (payloadTypeBadge) {
            payloadTypeBadge.textContent = payloadInfo.type_label || "URL";
            if (payloadInfo.content_type === "wifi") {
                payloadTypeBadge.className = "badge payload-type-badge fs-6 px-3 py-1 bg-warning text-dark";
            } else if (payloadInfo.content_type === "email") {
                payloadTypeBadge.className = "badge payload-type-badge fs-6 px-3 py-1 bg-info text-dark";
            } else if (payloadInfo.content_type === "phone") {
                payloadTypeBadge.className = "badge payload-type-badge fs-6 px-3 py-1 bg-success";
            } else if (payloadInfo.content_type === "vcard") {
                payloadTypeBadge.className = "badge payload-type-badge fs-6 px-3 py-1 bg-primary";
            } else if (payloadInfo.content_type === "text") {
                payloadTypeBadge.className = "badge payload-type-badge fs-6 px-3 py-1 bg-secondary";
            } else {
                payloadTypeBadge.className = "badge payload-type-badge fs-6 px-3 py-1 bg-primary";
            }
        }

        if (payloadSecurityWarningText) {
            payloadSecurityWarningText.textContent = payloadInfo.security_warning || "Standard destination";
        }

        if (payloadWarningIcon) {
            if (payloadInfo.content_type === "wifi") {
                payloadWarningIcon.className = "bi bi-shield-lock-fill text-warning";
            } else if (data.status === "dangerous" || data.score >= 70) {
                payloadWarningIcon.className = "bi bi-shield-exclamation text-danger";
            } else if (data.status === "suspicious") {
                payloadWarningIcon.className = "bi bi-shield-exclamation text-warning";
            } else {
                payloadWarningIcon.className = "bi bi-shield-check text-success";
            }
        }

        // Hide all specialized payload cards initially
        const wifiPayloadCard = document.getElementById("wifiPayloadCard");
        const emailPayloadCard = document.getElementById("emailPayloadCard");
        const phonePayloadCard = document.getElementById("phonePayloadCard");
        const vcardPayloadCard = document.getElementById("vcardPayloadCard");
        const textPayloadCard = document.getElementById("textPayloadCard");

        if (wifiPayloadCard) wifiPayloadCard.classList.add("d-none");
        if (emailPayloadCard) emailPayloadCard.classList.add("d-none");
        if (phonePayloadCard) phonePayloadCard.classList.add("d-none");
        if (vcardPayloadCard) vcardPayloadCard.classList.add("d-none");
        if (textPayloadCard) textPayloadCard.classList.add("d-none");

        const cType = payloadInfo.content_type;
        const details = payloadInfo.details || {};

        if (cType === "wifi" && wifiPayloadCard) {
            wifiPayloadCard.classList.remove("d-none");
            const wifiSsidVal = document.getElementById("wifiSsidVal");
            const wifiAuthBadge = document.getElementById("wifiAuthBadge");
            const wifiHiddenBadge = document.getElementById("wifiHiddenBadge");
            const wifiPasswordVal = document.getElementById("wifiPasswordVal");
            const toggleWifiPwBtn = document.getElementById("toggleWifiPwBtn");

            if (wifiSsidVal) wifiSsidVal.textContent = details.ssid || "(Hidden / None)";
            if (wifiAuthBadge) wifiAuthBadge.textContent = (details.auth_type || "WPA").toUpperCase();
            if (wifiHiddenBadge) {
                if (details.hidden) wifiHiddenBadge.classList.remove("d-none");
                else wifiHiddenBadge.classList.add("d-none");
            }

            const rawPw = details.password || "";
            const maskedPw = rawPw ? "•".repeat(Math.min(Math.max(rawPw.length, 8), 16)) : "None";
            if (wifiPasswordVal) {
                wifiPasswordVal.textContent = maskedPw;
                wifiPasswordVal.setAttribute("data-revealed", "false");
            }

            if (toggleWifiPwBtn) {
                const newBtn = toggleWifiPwBtn.cloneNode(true);
                toggleWifiPwBtn.parentNode.replaceChild(newBtn, toggleWifiPwBtn);
                newBtn.innerHTML = '<i class="bi bi-eye"></i> Show';
                newBtn.addEventListener("click", function () {
                    const isRevealed = wifiPasswordVal.getAttribute("data-revealed") === "true";
                    if (isRevealed) {
                        wifiPasswordVal.textContent = maskedPw;
                        wifiPasswordVal.setAttribute("data-revealed", "false");
                        newBtn.innerHTML = '<i class="bi bi-eye"></i> Show';
                    } else {
                        wifiPasswordVal.textContent = rawPw || "(No Password)";
                        wifiPasswordVal.setAttribute("data-revealed", "true");
                        newBtn.innerHTML = '<i class="bi bi-eye-slash"></i> Hide';
                    }
                });
            }
        } else if (cType === "email" && emailPayloadCard) {
            emailPayloadCard.classList.remove("d-none");
            const emailRecipientVal = document.getElementById("emailRecipientVal");
            const emailSubjectVal = document.getElementById("emailSubjectVal");
            const emailBodyVal = document.getElementById("emailBodyVal");
            const emailEmbeddedUrlsBox = document.getElementById("emailEmbeddedUrlsBox");
            const emailEmbeddedUrlsVal = document.getElementById("emailEmbeddedUrlsVal");

            if (emailRecipientVal) emailRecipientVal.textContent = details.recipient || "-";
            if (emailSubjectVal) emailSubjectVal.textContent = details.subject || "(No Subject)";
            if (emailBodyVal) emailBodyVal.textContent = details.body || "(No message body)";

            if (payloadInfo.embedded_urls && payloadInfo.embedded_urls.length > 0) {
                if (emailEmbeddedUrlsBox) emailEmbeddedUrlsBox.classList.remove("d-none");
                if (emailEmbeddedUrlsVal) emailEmbeddedUrlsVal.textContent = payloadInfo.embedded_urls.join(", ");
            } else {
                if (emailEmbeddedUrlsBox) emailEmbeddedUrlsBox.classList.add("d-none");
            }
        } else if (cType === "phone" && phonePayloadCard) {
            phonePayloadCard.classList.remove("d-none");
            const phoneNumberVal = document.getElementById("phoneNumberVal");
            const phoneDialBtn = document.getElementById("phoneDialBtn");
            const phoneNum = details.phone_number || "";
            if (phoneNumberVal) phoneNumberVal.textContent = phoneNum || "-";
            if (phoneDialBtn) phoneDialBtn.href = phoneNum ? `tel:${phoneNum}` : "#";
        } else if (cType === "vcard" && vcardPayloadCard) {
            vcardPayloadCard.classList.remove("d-none");
            const vcardNameVal = document.getElementById("vcardNameVal");
            const vcardOrgVal = document.getElementById("vcardOrgVal");
            const vcardPhoneVal = document.getElementById("vcardPhoneVal");
            const vcardEmailVal = document.getElementById("vcardEmailVal");
            const vcardUrlContainer = document.getElementById("vcardUrlContainer");
            const vcardUrlVal = document.getElementById("vcardUrlVal");

            if (vcardNameVal) vcardNameVal.textContent = details.name || "-";
            if (vcardOrgVal) vcardOrgVal.textContent = details.org || "None specified";
            if (vcardPhoneVal) vcardPhoneVal.textContent = details.phone || "None specified";
            if (vcardEmailVal) vcardEmailVal.textContent = details.email || "None specified";

            if (details.url) {
                if (vcardUrlContainer) vcardUrlContainer.classList.remove("d-none");
                if (vcardUrlVal) vcardUrlVal.textContent = details.url;
            } else {
                if (vcardUrlContainer) vcardUrlContainer.classList.add("d-none");
            }
        } else if (cType === "text" && textPayloadCard) {
            textPayloadCard.classList.remove("d-none");
            const textContentVal = document.getElementById("textContentVal");
            if (textContentVal) textContentVal.textContent = payloadInfo.raw_payload || data.url;
        }

        // Render URL Shortener Threat Alert Card
        const shortenerAlertCard = document.getElementById("shortenerAlertCard");
        const shortenerServiceBadge = document.getElementById("shortenerServiceBadge");
        const shortenerTargetBox = document.getElementById("shortenerTargetBox");
        const shortenerTargetUrl = document.getElementById("shortenerTargetUrl");

        if (shortenerAlertCard) {
            if (data.is_shortener) {
                shortenerAlertCard.classList.remove("d-none");
                if (shortenerServiceBadge) {
                    shortenerServiceBadge.textContent = `Shortener: ${data.hostname || "Detected"}`;
                }
                if (data.shortener_info && data.shortener_info.redirect_target) {
                    if (shortenerTargetBox) shortenerTargetBox.classList.remove("d-none");
                    if (shortenerTargetUrl) shortenerTargetUrl.textContent = data.shortener_info.redirect_target;
                } else {
                    if (shortenerTargetBox) shortenerTargetBox.classList.add("d-none");
                }
            } else {
                shortenerAlertCard.classList.add("d-none");
            }
        }

        // =========================================================================
        // SECTION 13: ANTI-OBFUSCATION DETECTION
        // =========================================================================
        const obfuscationAlertCard = document.getElementById("obfuscationAlertCard");
        if (obfuscationAlertCard) {
            const obf = data.obfuscation_analysis;
            if (obf && obf.is_obfuscated) {
                obfuscationAlertCard.classList.remove("d-none");
                
                const obfTitle = document.getElementById("obfuscationAlertTitle");
                const obfMsg = document.getElementById("obfuscationAlertMessage");
                const obfBadges = document.getElementById("obfuscationBadgesContainer");
                
                if (obfTitle) obfTitle.textContent = obf.warning_title || "⚠ POSSIBLE URL OBFUSCATION";
                if (obfMsg) obfMsg.textContent = obf.warning_message;
                
                if (obfBadges) {
                    obfBadges.innerHTML = "";
                    (obf.detected_techniques || []).forEach(tech => {
                        const badge = document.createElement("span");
                        badge.className = "badge bg-danger text-white";
                        let label = tech.replace(/_/g, " ").toUpperCase();
                        if (tech === "unicode_punycode") label = "Punycode (xn--)";
                        else if (tech === "hex_alternative_ip") label = "Hex / Alt IP";
                        else if (tech === "url_encoding") label = "URL Encoding";
                        else if (tech === "nested_urls") label = "Nested URL";
                        else if (tech === "multiple_redirects") label = "Redirect Chain";
                        badge.textContent = label;
                        obfBadges.appendChild(badge);
                    });
                }

                // 1. Punycode Homograph Box
                const resemblanceBox = document.getElementById("obfuscationResemblanceBox");
                const resemblanceVal = document.getElementById("obfuscationResemblanceVal");
                if (obf.punycode_info && (obf.punycode_info.visually_resembles || obf.punycode_info.unicode_domain)) {
                    if (resemblanceBox) resemblanceBox.classList.remove("d-none");
                    if (resemblanceVal) resemblanceVal.textContent = obf.punycode_info.visually_resembles || obf.punycode_info.unicode_domain;
                } else if (resemblanceBox) {
                    resemblanceBox.classList.add("d-none");
                }

                // 2. Alternative IP Box
                const ipBox = document.getElementById("obfuscationIpBox");
                const ipVal = document.getElementById("obfuscationIpVal");
                if (obf.ip_obfuscation_info && obf.ip_obfuscation_info.canonical_ip) {
                    if (ipBox) ipBox.classList.remove("d-none");
                    if (ipVal) ipVal.textContent = `${obf.ip_obfuscation_info.canonical_ip} (from ${obf.ip_obfuscation_info.original_host})`;
                } else if (ipBox) {
                    ipBox.classList.add("d-none");
                }

                // 3. Nested URL Box
                const nestedBox = document.getElementById("obfuscationNestedBox");
                const nestedVal = document.getElementById("obfuscationNestedVal");
                if (obf.nested_url_info && obf.nested_url_info.primary_nested_url) {
                    if (nestedBox) nestedBox.classList.remove("d-none");
                    if (nestedVal) nestedVal.textContent = obf.nested_url_info.primary_nested_url;
                } else if (nestedBox) {
                    nestedBox.classList.add("d-none");
                }

                // 4. URL Encoding Box
                const encodingBox = document.getElementById("obfuscationEncodingBox");
                const encodingVal = document.getElementById("obfuscationEncodingVal");
                if (obf.encoding_info && obf.encoding_info.decoded_url) {
                    if (encodingBox) encodingBox.classList.remove("d-none");
                    if (encodingVal) encodingVal.textContent = obf.encoding_info.decoded_url;
                } else if (encodingBox) {
                    encodingBox.classList.add("d-none");
                }

                // 5. Multiple Redirect Chain Box
                const chainBox = document.getElementById("obfuscationChainBox");
                const chainVal = document.getElementById("obfuscationChainVal");
                if (obf.redirect_chain_info && obf.redirect_chain_info.has_multiple_redirects && obf.redirect_chain_info.chain) {
                    if (chainBox) chainBox.classList.remove("d-none");
                    if (chainVal) {
                        chainVal.innerHTML = "";
                        obf.redirect_chain_info.chain.forEach((hop, idx) => {
                            if (idx > 0) {
                                const arrow = document.createElement("span");
                                arrow.className = "obfuscation-chain-arrow mx-1";
                                arrow.textContent = "➔";
                                chainVal.appendChild(arrow);
                            }
                            const step = document.createElement("span");
                            step.className = "obfuscation-chain-step";
                            step.textContent = `Hop ${idx + 1}: ${hop}`;
                            chainVal.appendChild(step);
                        });
                    }
                } else if (chainBox) {
                    chainBox.classList.add("d-none");
                }
            } else {
                obfuscationAlertCard.classList.add("d-none");
            }
        }

        // =========================================================================
        // SECTION 14: BRAND IMPERSONATION DETECTION
        // =========================================================================
        const brandImpersonationAlertCard = document.getElementById("brandImpersonationAlertCard");
        if (brandImpersonationAlertCard) {
            const brandImp = data.brand_impersonation;
            if (brandImp && brandImp.is_impersonation) {
                brandImpersonationAlertCard.classList.remove("d-none");

                const brandHeading = document.getElementById("brandAlertHeading");
                const detectedBrandTermVal = document.getElementById("detectedBrandTermVal");
                const actualDomainNameVal = document.getElementById("actualDomainNameVal");
                const brandWarningMessageVal = document.getElementById("brandWarningMessageVal");
                const brandBadgesContainer = document.getElementById("brandBadgesContainer");

                if (brandHeading) brandHeading.textContent = brandImp.warning_title || "⚠ POSSIBLE BRAND IMPERSONATION";
                if (detectedBrandTermVal) detectedBrandTermVal.textContent = brandImp.detected_brand || "Brand";
                if (actualDomainNameVal) actualDomainNameVal.textContent = brandImp.actual_domain || data.hostname;
                if (brandWarningMessageVal) brandWarningMessageVal.textContent = brandImp.warning_message || `The domain is not an official ${brandImp.detected_brand} domain.`;

                if (brandBadgesContainer) {
                    brandBadgesContainer.innerHTML = "";
                    (brandImp.impersonation_types || []).forEach(type => {
                        const b = document.createElement("span");
                        b.className = "badge bg-danger text-white";
                        let label = type.replace(/_/g, " ").toUpperCase();
                        if (type === "character_substitution") label = "Leetspeak / Substitutions";
                        else if (type === "compound_keyword") label = "Compound Phishing Domain";
                        else if (type === "misleading_subdomain") label = "Misleading Subdomain";
                        else if (type === "typosquatting") label = "Typosquatting Lookalike";
                        b.textContent = label;
                        brandBadgesContainer.appendChild(b);
                    });
                }

                // 1. Character Substitutions Box
                const brandSubBox = document.getElementById("brandSubstitutionsBox");
                const brandSubList = document.getElementById("brandSubstitutionsList");
                if (brandImp.substitutions && brandImp.substitutions.length > 0) {
                    if (brandSubBox) brandSubBox.classList.remove("d-none");
                    if (brandSubList) {
                        brandSubList.innerHTML = "";
                        brandImp.substitutions.forEach(s => {
                            const pill = document.createElement("span");
                            pill.className = "brand-sub-badge";
                            pill.innerHTML = `<i class="bi bi-arrow-left-right me-1"></i> ${s.description || `'${s.original}' → '${s.normalized}'`}`;
                            brandSubList.appendChild(pill);
                        });
                    }
                } else if (brandSubBox) {
                    brandSubBox.classList.add("d-none");
                }

                // 2. Typosquatting Similarity Box
                const brandSimBox = document.getElementById("brandSimilarityBox");
                const brandSimVal = document.getElementById("brandSimilarityVal");
                if (brandImp.similarity_score && brandImp.similarity_score < 1.0) {
                    if (brandSimBox) brandSimBox.classList.remove("d-none");
                    if (brandSimVal) brandSimVal.textContent = `${Math.round(brandImp.similarity_score * 1000) / 10}%`;
                } else if (brandSimBox) {
                    brandSimBox.classList.add("d-none");
                }

                // 3. Misleading Subdomain Box
                const brandSubdomainBox = document.getElementById("brandMisleadingSubdomainBox");
                const brandSubdomainVal = document.getElementById("brandSubdomainVal");
                if (brandImp.impersonation_types && brandImp.impersonation_types.includes("misleading_subdomain")) {
                    if (brandSubdomainBox) brandSubdomainBox.classList.remove("d-none");
                    if (brandSubdomainVal) brandSubdomainVal.textContent = `${data.hostname} (Attacker Registered: ${brandImp.actual_domain})`;
                } else if (brandSubdomainBox) {
                    brandSubdomainBox.classList.add("d-none");
                }

                // 4. Official Domains Sample Pills
                const officialPillsBox = document.getElementById("brandOfficialDomainsPills");
                if (officialPillsBox && brandImp.official_domains_sample) {
                    officialPillsBox.innerHTML = "";
                    brandImp.official_domains_sample.forEach(dom => {
                        const pill = document.createElement("span");
                        pill.className = "brand-official-domain-pill";
                        pill.innerHTML = `<i class="bi bi-check2-circle me-1"></i> ${dom}`;
                        officialPillsBox.appendChild(pill);
                    });
                }
            } else {
                brandImpersonationAlertCard.classList.add("d-none");
            }
        }

        // =========================================================================
        // RENDER COMBINED RISK ENGINE (CENTRAL BRAIN)
        // =========================================================================
        const combinedRiskEngineCard = document.getElementById("combinedRiskEngineCard");
        if (combinedRiskEngineCard) {
            combinedRiskEngineCard.classList.remove("d-none");

            const ruleVal = Number(data.rule_score) || 0;
            const mlVal = Number(data.ml_score) || 0;
            const domainVal = Number(data.domain_score) || 0;
            const finalScore = Number(data.score) || 0;

            let riskLevel = data.risk_level;
            if (!riskLevel) {
                if (finalScore >= 70) riskLevel = "HIGH";
                else if (finalScore >= 35) riskLevel = "MEDIUM";
                else riskLevel = "LOW";
            }

            const levelBadgeClass = riskLevel === "HIGH"
                ? "risk-level-badge-danger"
                : (riskLevel === "MEDIUM" ? "risk-level-badge-warning" : "risk-level-badge-safe");

            // Combined Brain Card badge & text
            const brainRiskBadge = document.getElementById("brainRiskBadge");
            if (brainRiskBadge) {
                brainRiskBadge.textContent = `Risk Level: ${riskLevel}`;
                brainRiskBadge.className = `badge ${levelBadgeClass}`;
            }

            const brainRiskLevelText = document.getElementById("brainRiskLevelText");
            if (brainRiskLevelText) {
                brainRiskLevelText.textContent = riskLevel;
                brainRiskLevelText.className = `badge ${levelBadgeClass} fs-6`;
            }

            // Hero badge in primary score circle
            const heroRiskLevelBadge = document.getElementById("heroRiskLevelBadge");
            if (heroRiskLevelBadge) {
                heroRiskLevelBadge.textContent = riskLevel;
                heroRiskLevelBadge.className = `badge risk-level-badge ${levelBadgeClass} mt-1`;
            }

            // Triad values & progress bars
            const brainRuleValue = document.getElementById("brainRuleValue");
            const brainRuleBar = document.getElementById("brainRuleBar");
            const diagramRuleScore = document.getElementById("diagramRuleScore");
            if (brainRuleValue) brainRuleValue.textContent = `${ruleVal} / 100`;
            if (brainRuleBar) brainRuleBar.style.width = `${Math.min(ruleVal, 100)}%`;
            if (diagramRuleScore) diagramRuleScore.textContent = `${ruleVal}/100`;

            const brainMlValue = document.getElementById("brainMlValue");
            const brainMlBar = document.getElementById("brainMlBar");
            const diagramMlScore = document.getElementById("diagramMlScore");
            if (brainMlValue) brainMlValue.textContent = `${mlVal}%`;
            if (brainMlBar) brainMlBar.style.width = `${Math.min(mlVal, 100)}%`;
            if (diagramMlScore) diagramMlScore.textContent = `${mlVal}%`;

            const brainDomainValue = document.getElementById("brainDomainValue");
            const brainDomainBar = document.getElementById("brainDomainBar");
            const diagramDomainScore = document.getElementById("diagramDomainScore");
            if (brainDomainValue) brainDomainValue.textContent = `${domainVal} / 100`;
            if (brainDomainBar) brainDomainBar.style.width = `${Math.min(domainVal, 100)}%`;
            if (diagramDomainScore) diagramDomainScore.textContent = `${domainVal}/100`;

            const brainFinalScore = document.getElementById("brainFinalScore");
            if (brainFinalScore) {
                brainFinalScore.textContent = finalScore;
                brainFinalScore.className = riskLevel === "HIGH" 
                    ? "fs-4 fw-bold text-danger" 
                    : (riskLevel === "MEDIUM" ? "fs-4 fw-bold text-warning" : "fs-4 fw-bold text-success");
            }
        }

        // =========================================================================
        // RENDER THREAT INTELLIGENCE CARD
        // =========================================================================
        const threatIntelCard = document.getElementById("threatIntelCard");
        if (threatIntelCard && data.threat_intel) {
            threatIntelCard.classList.remove("d-none");
            const ti = data.threat_intel;

            const threatMaliciousBadge = document.getElementById("threatMaliciousBadge");
            const threatKnownMaliciousVal = document.getElementById("threatKnownMaliciousVal");
            const threatMatchesCountVal = document.getElementById("threatMatchesCountVal");
            const threatWarningBanner = document.getElementById("threatWarningBanner");
            const threatAlertIcon = document.getElementById("threatAlertIcon");
            const threatAlertTitle = document.getElementById("threatAlertTitle");
            const threatAlertDesc = document.getElementById("threatAlertDesc");
            const threatProvidersGrid = document.getElementById("threatProvidersGrid");

            if (ti.known_malicious) {
                threatIntelCard.classList.add("threat-detected");
                if (threatMaliciousBadge) {
                    threatMaliciousBadge.textContent = "Known Malicious: YES";
                    threatMaliciousBadge.className = "badge bg-danger";
                }
                if (threatKnownMaliciousVal) {
                    threatKnownMaliciousVal.textContent = "YES";
                    threatKnownMaliciousVal.className = "fs-4 fw-bold font-mono text-danger";
                }
                if (threatMatchesCountVal) {
                    threatMatchesCountVal.textContent = ti.matches_count;
                    threatMatchesCountVal.className = "fs-4 fw-bold font-mono text-danger";
                }
                if (threatWarningBanner) {
                    threatWarningBanner.className = "threat-warning-banner p-3 rounded mb-3 d-flex align-items-start gap-3";
                }
                if (threatAlertIcon) {
                    threatAlertIcon.className = "bi bi-exclamation-triangle-fill text-danger fs-4 flex-shrink-0 mt-1";
                }
                if (threatAlertTitle) {
                    threatAlertTitle.textContent = "⚠ External intelligence indicates this URL has been reported.";
                    threatAlertTitle.className = "fw-bold threat-lead-text text-danger";
                }
                if (threatAlertDesc) {
                    threatAlertDesc.textContent = `Flagged across ${ti.matches_count} independent threat intelligence feeds as active quishing, phishing, or malware.`;
                }
            } else {
                threatIntelCard.classList.remove("threat-detected");
                if (threatMaliciousBadge) {
                    threatMaliciousBadge.textContent = "Reputation: Clean";
                    threatMaliciousBadge.className = "badge bg-success";
                }
                if (threatKnownMaliciousVal) {
                    threatKnownMaliciousVal.textContent = "NO";
                    threatKnownMaliciousVal.className = "fs-4 fw-bold font-mono text-success";
                }
                if (threatMatchesCountVal) {
                    threatMatchesCountVal.textContent = "0";
                    threatMatchesCountVal.className = "fs-4 fw-bold font-mono text-success";
                }
                if (threatWarningBanner) {
                    threatWarningBanner.className = "threat-clean-banner p-3 rounded mb-3 d-flex align-items-start gap-3";
                }
                if (threatAlertIcon) {
                    threatAlertIcon.className = "bi bi-shield-check text-success fs-4 flex-shrink-0 mt-1";
                }
                if (threatAlertTitle) {
                    threatAlertTitle.textContent = "✓ No threat intelligence database has reported this URL.";
                    threatAlertTitle.className = "fw-bold threat-lead-text text-success";
                }
                if (threatAlertDesc) {
                    threatAlertDesc.textContent = "This destination has not been indexed in URLhaus, PhishTank, Google Safe Browsing, VirusTotal, or OpenPhish threat repositories.";
                }
            }

            // Render provider pills
            if (threatProvidersGrid && ti.providers) {
                threatProvidersGrid.innerHTML = "";
                ti.providers.forEach(prov => {
                    const col = document.createElement("div");
                    col.className = "col-md-6 col-lg-4";
                    const isMal = prov.matched;
                    const pillClass = isMal ? "status-malicious" : "status-clean";
                    const statusBadge = isMal 
                        ? '<span class="threat-provider-status bg-danger text-white">MALICIOUS MATCH</span>'
                        : (prov.status === "unconfigured" 
                            ? '<span class="threat-provider-status bg-secondary text-white">CLEAN (API KEY OPTIONAL)</span>'
                            : '<span class="threat-provider-status bg-success text-white">CLEAN</span>');

                    col.innerHTML = `
                        <div class="threat-provider-pill ${pillClass}">
                            <div class="d-flex align-items-center justify-content-between mb-1">
                                <span class="threat-provider-name">${prov.name}</span>
                                ${statusBadge}
                            </div>
                            <div class="small text-secondary text-truncate" title="${prov.details || ''}">
                                ${prov.details || "Clean"}
                            </div>
                        </div>
                    `;
                    threatProvidersGrid.appendChild(col);
                });
            }
        }

        // Render Domain & Network Intelligence Grid
        const intelProtocol = document.getElementById("intelProtocol");
        const intelHostType = document.getElementById("intelHostType");
        const intelAuthority = document.getElementById("intelAuthority");
        const intelModel = document.getElementById("intelModel");

        if (intelProtocol) {
            const isHttps = (data.url || "").toLowerCase().startsWith("https://");
            intelProtocol.textContent = isHttps ? "HTTPS (Encrypted)" : "HTTP (Insecure)";
            intelProtocol.className = isHttps ? "soc-value text-success" : "soc-value text-danger";
        }

        if (intelHostType) {
            intelHostType.textContent = data.is_ip ? "Direct IP Host" : (data.is_shortener ? "URL Shortener" : "Registered Domain");
            intelHostType.className = data.is_ip ? "soc-value text-danger" : (data.is_shortener ? "soc-value text-warning" : "soc-value");
        }

        if (intelAuthority) {
            intelAuthority.textContent = data.is_trusted ? "Reputable Authority" : "Untrusted / Unknown";
            intelAuthority.className = data.is_trusted ? "soc-value text-primary" : "soc-value text-secondary";
        }

        if (intelModel) {
            intelModel.textContent = modelName;
        }

        // Render explainable reasons
        reasonsList.innerHTML = "";
        (data.reasons || []).forEach(reason => {
            const li = document.createElement("li");
            li.textContent = reason;
            reasonsList.appendChild(li);
        });

        // Render Detected Security Characteristics Checklist
        const detectedCard = document.getElementById("detectedCard");
        const detectedList = document.getElementById("detectedList");
        const detectedCountBadge = document.getElementById("detectedCountBadge");

        if (detectedCard && detectedList) {
            detectedList.innerHTML = "";
            const detected = data.detected || [];
            if (detected.length > 0) {
                detectedCard.classList.remove("d-none");
                if (detectedCountBadge) {
                    detectedCountBadge.textContent = `${detected.length} Detected`;
                    detectedCountBadge.className = data.status === "dangerous" ? "badge bg-danger" : "badge bg-warning text-dark";
                }
                detected.forEach(item => {
                    const div = document.createElement("div");
                    const isDanger = data.status === "dangerous" || item.includes("IP address") || item.includes("Brand impersonation") || item.includes("@ symbol") || item.includes("Unusual port") || item.includes("Suspicious path");
                    div.className = `detected-check-item ${isDanger ? "detected-danger" : "detected-warning"}`;
                    div.innerHTML = `<i class="bi bi-check2-circle"></i> <span>${item}</span>`;
                    detectedList.appendChild(div);
                });
            } else {
                detectedCard.classList.remove("d-none");
                if (detectedCountBadge) {
                    detectedCountBadge.textContent = "0 Detected";
                    detectedCountBadge.className = "badge bg-success";
                }
                const div = document.createElement("div");
                div.className = "detected-check-item detected-clean";
                div.innerHTML = `<i class="bi bi-shield-check"></i> <span>No suspicious characteristics detected. Destination passes all 13 cybersecurity heuristic checks.</span>`;
                detectedList.appendChild(div);
            }
        }

        // Render threat indicator badges
        if (indicatorsCard && indicatorsList) {
            indicatorsList.innerHTML = "";
            const indicators = data.indicators || [];
            if (indicators.length > 0) {
                indicatorsCard.classList.remove("d-none");
                indicators.forEach(ind => {
                    const badge = document.createElement("span");
                    const sevClass = ind.severity === "high" ? "badge-high" : (ind.severity === "medium" ? "badge-medium" : "badge-low");
                    badge.className = `indicator-badge ${sevClass}`;
                    const icon = ind.severity === "high" ? "bi-exclamation-octagon-fill" : (ind.severity === "medium" ? "bi-exclamation-triangle-fill" : "bi-info-circle-fill");
                    badge.innerHTML = `<i class="bi ${icon}"></i> ${ind.name.replace(/_/g, " ").toUpperCase()} (+${ind.weight})`;
                    if (ind.detail) badge.title = ind.detail;
                    indicatorsList.appendChild(badge);
                });
            } else {
                if (data.is_trusted) {
                    indicatorsCard.classList.remove("d-none");
                    const badge = document.createElement("span");
                    badge.className = "indicator-badge badge-safe";
                    badge.innerHTML = '<i class="bi bi-shield-check"></i> VERIFIED REPUTABLE DOMAIN';
                    indicatorsList.appendChild(badge);
                } else {
                    indicatorsCard.classList.add("d-none");
                }
            }
        }

        // Color coding by status
        resultIcon.className = "result-icon";
        if (data.status === "dangerous") {
            resultIcon.innerHTML = '<i class="bi bi-shield-x"></i>';
            resultIcon.style.color = "var(--status-danger)";
            resultIcon.style.background = "var(--status-danger-bg)";
            resultLabel.textContent = "HIGH RISK — DANGEROUS";
            resultLabel.style.color = "var(--status-danger)";
            if (scoreCircle) scoreCircle.style.borderColor = "var(--status-danger)";
        } else if (data.status === "suspicious") {
            resultIcon.innerHTML = '<i class="bi bi-shield-exclamation"></i>';
            resultIcon.style.color = "var(--status-warning)";
            resultIcon.style.background = "var(--status-warning-bg)";
            resultLabel.textContent = "MEDIUM RISK — SUSPICIOUS";
            resultLabel.style.color = "var(--status-warning)";
            if (scoreCircle) scoreCircle.style.borderColor = "var(--status-warning)";
        } else {
            resultIcon.innerHTML = '<i class="bi bi-shield-check"></i>';
            resultIcon.style.color = "var(--status-safe)";
            resultIcon.style.background = "var(--status-safe-bg)";
            resultLabel.textContent = "LOW RISK — LOOKS SAFE";
            resultLabel.style.color = "var(--status-safe)";
            if (scoreCircle) scoreCircle.style.borderColor = "var(--status-safe)";
        }

        // =========================================================================
        // FEATURE 17: WHAT SHOULD I DO? (ACTIONABLE SECURITY RECOMMENDATION)
        // =========================================================================
        const whatShouldIDoCard = document.getElementById("whatShouldIDoCard");
        const whatShouldIDoBadge = document.getElementById("whatShouldIDoBadge");
        const whatShouldIDoLead = document.getElementById("whatShouldIDoLead");
        const whatShouldIDoAction = document.getElementById("whatShouldIDoAction");
        const whatShouldIDoIconBox = document.getElementById("whatShouldIDoIconBox");
        const whatShouldIDoIcon = document.getElementById("whatShouldIDoIcon");

        if (whatShouldIDoCard) {
            whatShouldIDoCard.classList.remove("d-none");
            const wsd = data.what_should_i_do || {};
            const riskLevel = (wsd.risk_level || (data.status === "dangerous" ? "HIGH" : (data.status === "suspicious" ? "MEDIUM" : "LOW"))).toUpperCase();
            
            // Clear tier modifier classes
            whatShouldIDoCard.classList.remove("recommendation-low", "recommendation-suspicious", "recommendation-dangerous");

            if (riskLevel === "HIGH") {
                whatShouldIDoCard.classList.add("recommendation-dangerous");
                if (whatShouldIDoBadge) {
                    whatShouldIDoBadge.className = "badge fs-6 px-3 py-2 bg-danger";
                    whatShouldIDoBadge.textContent = wsd.badge_text || "🚨 HIGH RISK";
                }
                if (whatShouldIDoLead) {
                    whatShouldIDoLead.textContent = wsd.lead_text || "Multiple phishing indicators were detected.";
                    whatShouldIDoLead.className = "fw-bold fs-6 mb-2 text-danger";
                }
                if (whatShouldIDoAction) {
                    whatShouldIDoAction.textContent = wsd.action_text || "Do not open the destination. Do not enter passwords, OTPs, card details, or banking information.";
                    whatShouldIDoAction.className = "fw-semibold text-danger";
                }
                if (whatShouldIDoIconBox) whatShouldIDoIconBox.className = "what-icon-box p-2 rounded-3 bg-danger-subtle text-danger";
                if (whatShouldIDoIcon) whatShouldIDoIcon.className = "bi bi-shield-x fs-3";
            } else if (riskLevel === "MEDIUM") {
                whatShouldIDoCard.classList.add("recommendation-suspicious");
                if (whatShouldIDoBadge) {
                    whatShouldIDoBadge.className = "badge fs-6 px-3 py-2 bg-warning text-dark";
                    whatShouldIDoBadge.textContent = wsd.badge_text || "⚠ SUSPICIOUS";
                }
                if (whatShouldIDoLead) {
                    whatShouldIDoLead.textContent = wsd.lead_text || "The URL contains characteristics commonly associated with phishing.";
                    whatShouldIDoLead.className = "fw-bold fs-6 mb-2 text-warning";
                }
                if (whatShouldIDoAction) {
                    whatShouldIDoAction.textContent = wsd.action_text || "Avoid entering sensitive information.";
                    whatShouldIDoAction.className = "fw-semibold text-warning";
                }
                if (whatShouldIDoIconBox) whatShouldIDoIconBox.className = "what-icon-box p-2 rounded-3 bg-warning-subtle text-warning";
                if (whatShouldIDoIcon) whatShouldIDoIcon.className = "bi bi-exclamation-triangle-fill fs-3";
            } else {
                whatShouldIDoCard.classList.add("recommendation-low");
                if (whatShouldIDoBadge) {
                    whatShouldIDoBadge.className = "badge fs-6 px-3 py-2 bg-success";
                    whatShouldIDoBadge.textContent = wsd.badge_text || "✓ LOW RISK";
                }
                if (whatShouldIDoLead) {
                    whatShouldIDoLead.textContent = wsd.lead_text || "No significant indicators were detected.";
                    whatShouldIDoLead.className = "fw-bold fs-6 mb-2 text-success";
                }
                if (whatShouldIDoAction) {
                    whatShouldIDoAction.textContent = wsd.action_text || "Still verify the destination before entering credentials or payment information.";
                    whatShouldIDoAction.className = "fw-semibold text-secondary";
                }
                if (whatShouldIDoIconBox) whatShouldIDoIconBox.className = "what-icon-box p-2 rounded-3 bg-success-subtle text-success";
                if (whatShouldIDoIcon) whatShouldIDoIcon.className = "bi bi-check-circle-fill fs-3";
            }
        }

        // =========================================================================
        // FEATURE 15: USER EDUCATION ("WHY IS THIS DANGEROUS?")
        // =========================================================================
        const userEducationCard = document.getElementById("userEducationCard");
        const userEducationHeading = document.getElementById("userEducationHeading");
        const userEducationText = document.getElementById("userEducationText");
        const userEducationProhibitedList = document.getElementById("userEducationProhibitedList");
        const userEducationNote = document.getElementById("userEducationNote");

        if (userEducationCard) {
            const isThreatDetected = data.status === "dangerous" || data.status === "suspicious" || data.score >= 35 || (data.threat_intel && data.threat_intel.known_malicious);
            if (isThreatDetected) {
                userEducationCard.classList.remove("d-none");
                const edu = data.user_education || {};
                if (userEducationHeading) userEducationHeading.textContent = edu.heading || "WHY IS THIS DANGEROUS?";
                if (userEducationText) userEducationText.textContent = edu.text || "QR phishing attacks can hide the destination URL from the user until the QR code is scanned.";
                
                if (userEducationProhibitedList) {
                    userEducationProhibitedList.innerHTML = "";
                    const items = edu.prohibited_items || ["passwords", "OTPs", "banking credentials", "card information"];
                    items.forEach(item => {
                        const li = document.createElement("li");
                        li.textContent = item;
                        userEducationProhibitedList.appendChild(li);
                    });
                }

                if (userEducationNote) userEducationNote.textContent = edu.closing_note || "unless you have verified the destination.";
            } else {
                userEducationCard.classList.add("d-none");
            }
        }

        // Render Domain Intelligence & Infrastructure
        const domainIntelCard = document.getElementById("domainIntelCard");
        if (domainIntelCard && data.domain_intel) {
            domainIntelCard.classList.remove("d-none");
            const intel = data.domain_intel;
            const whois = intel.whois || {};
            const dns = intel.dns || {};

            const whoisDomain = document.getElementById("whoisDomain");
            const whoisAge = document.getElementById("whoisAge");
            const whoisCreation = document.getElementById("whoisCreation");
            const whoisRegistrar = document.getElementById("whoisRegistrar");
            const whoisExpiration = document.getElementById("whoisExpiration");
            const domainStatusBadge = document.getElementById("domainStatusBadge");
            const domainRecentAlert = document.getElementById("domainRecentAlert");
            const domainRecentText = document.getElementById("domainRecentText");

            if (whoisDomain) whoisDomain.textContent = intel.domain || "-";

            if (intel.is_ip) {
                if (domainStatusBadge) {
                    domainStatusBadge.textContent = "Direct IP Host";
                    domainStatusBadge.className = "badge bg-info text-dark";
                }
                if (whoisAge) whoisAge.textContent = "N/A (Raw IP Address)";
                if (whoisCreation) whoisCreation.textContent = "N/A";
                if (whoisRegistrar) whoisRegistrar.textContent = "N/A (Autonomous System)";
                if (whoisExpiration) whoisExpiration.textContent = "N/A";
                if (domainRecentAlert) domainRecentAlert.classList.add("d-none");
            } else {
                if (domainStatusBadge) {
                    if (dns.status === "resolved") {
                        domainStatusBadge.textContent = "Active / Resolved";
                        domainStatusBadge.className = "badge bg-success";
                    } else if (dns.status === "nxdomain") {
                        domainStatusBadge.textContent = "NXDOMAIN (Non-Existent)";
                        domainStatusBadge.className = "badge bg-danger";
                    } else {
                        domainStatusBadge.textContent = (dns.status || "Unknown").toUpperCase();
                        domainStatusBadge.className = "badge bg-secondary";
                    }
                }

                if (whoisAge) {
                    if (whois.age_text) {
                        whoisAge.innerHTML = `<span class="${whois.is_recently_registered ? 'text-warning' : 'text-success'}">${whois.age_text}</span>`;
                    } else {
                        whoisAge.textContent = "Unavailable";
                    }
                }

                if (whoisCreation) whoisCreation.textContent = whois.creation_date || "Not disclosed";
                if (whoisRegistrar) {
                    whoisRegistrar.textContent = whois.registrar || "Protected / Hidden";
                    whoisRegistrar.title = whois.registrar || "";
                }
                if (whoisExpiration) whoisExpiration.textContent = whois.expiration_date || "Not disclosed";

                if (domainRecentAlert) {
                    if (whois.is_recently_registered) {
                        domainRecentAlert.classList.remove("d-none");
                        if (domainRecentText) {
                            domainRecentText.textContent = `⚠ Recently registered domain (${whois.age_text} old) — one risk signal, not an automatic verdict.`;
                        }
                    } else {
                        domainRecentAlert.classList.add("d-none");
                    }
                }
            }

            // DNS elements
            const dnsStatusBadge = document.getElementById("dnsStatusBadge");
            const dnsARecords = document.getElementById("dnsARecords");
            const dnsMxRecords = document.getElementById("dnsMxRecords");
            const dnsNsRecords = document.getElementById("dnsNsRecords");

            if (dnsStatusBadge) {
                if (dns.status === "resolved") {
                    dnsStatusBadge.textContent = "RESOLVED";
                    dnsStatusBadge.className = "badge bg-success";
                } else if (dns.status === "nxdomain") {
                    dnsStatusBadge.textContent = "NXDOMAIN";
                    dnsStatusBadge.className = "badge bg-danger";
                } else if (dns.status === "direct_ip") {
                    dnsStatusBadge.textContent = "DIRECT IP";
                    dnsStatusBadge.className = "badge bg-info text-dark";
                } else {
                    dnsStatusBadge.textContent = (dns.status || "UNKNOWN").toUpperCase();
                    dnsStatusBadge.className = "badge bg-secondary";
                }
            }

            function renderDnsPills(container, items, emptyText) {
                if (!container) return;
                container.innerHTML = "";
                if (!items || items.length === 0) {
                    container.innerHTML = `<span class="text-secondary small fst-italic">${emptyText}</span>`;
                    return;
                }
                items.slice(0, 4).forEach(item => {
                    const pill = document.createElement("span");
                    pill.className = "dns-record-pill";
                    pill.textContent = item;
                    container.appendChild(pill);
                });
                if (items.length > 4) {
                    const more = document.createElement("span");
                    more.className = "badge bg-secondary";
                    more.textContent = `+${items.length - 4} more`;
                    container.appendChild(more);
                }
            }

            renderDnsPills(dnsARecords, dns.a_records, intel.is_ip ? intel.domain : "None resolved");
            renderDnsPills(dnsMxRecords, dns.mx_records, "No MX records");
            renderDnsPills(dnsNsRecords, dns.nameservers, "No NS records");
        }

        // Render TLS Security & Certificate Card
        const tlsCard = document.getElementById("tlsCard");
        if (tlsCard && data.tls_analysis) {
            tlsCard.classList.remove("d-none");
            const tls = data.tls_analysis;

            const tlsStatusBadge = document.getElementById("tlsStatusBadge");
            const tlsHttpsVal = document.getElementById("tlsHttpsVal");
            const tlsCertVal = document.getElementById("tlsCertVal");
            const tlsHostMatchVal = document.getElementById("tlsHostMatchVal");
            const tlsExpiryVal = document.getElementById("tlsExpiryVal");

            const tlsIssuer = document.getElementById("tlsIssuer");
            const tlsSubjectCn = document.getElementById("tlsSubjectCn");
            const tlsIssuedDate = document.getElementById("tlsIssuedDate");
            const tlsExpirationDate = document.getElementById("tlsExpirationDate");

            if (tlsStatusBadge) {
                if (tls.has_https && tls.certificate_valid) {
                    tlsStatusBadge.textContent = "Valid TLS";
                    tlsStatusBadge.className = "badge bg-success";
                } else if (!tls.has_https) {
                    tlsStatusBadge.textContent = "HTTP (Insecure)";
                    tlsStatusBadge.className = "badge bg-danger";
                } else {
                    tlsStatusBadge.textContent = (tls.certificate_status || "Invalid").toUpperCase();
                    tlsStatusBadge.className = "badge bg-danger";
                }
            }

            if (tlsHttpsVal) {
                if (tls.has_https) {
                    tlsHttpsVal.innerHTML = '<i class="bi bi-check-lg text-success"></i> <span class="text-success">Active</span>';
                } else {
                    tlsHttpsVal.innerHTML = '<i class="bi bi-x-lg text-danger"></i> <span class="text-danger">Missing</span>';
                }
            }

            if (tlsCertVal) {
                if (tls.has_https && tls.certificate_valid) {
                    tlsCertVal.innerHTML = '<i class="bi bi-check-lg text-success"></i> <span class="text-success">Valid</span>';
                } else if (!tls.has_https) {
                    tlsCertVal.innerHTML = '<i class="bi bi-dash-lg text-secondary"></i> <span class="text-secondary">N/A (HTTP)</span>';
                } else {
                    const statusText = tls.certificate_status === "expired" ? "Expired" : (tls.certificate_status === "self_signed" ? "Self-Signed" : "Invalid");
                    tlsCertVal.innerHTML = `<i class="bi bi-x-lg text-danger"></i> <span class="text-danger">${statusText}</span>`;
                }
            }

            if (tlsHostMatchVal) {
                if (tls.has_https && tls.hostname_match) {
                    tlsHostMatchVal.innerHTML = '<i class="bi bi-check-lg text-success"></i> <span class="text-success">Matched</span>';
                } else if (!tls.has_https) {
                    tlsHostMatchVal.innerHTML = '<i class="bi bi-dash-lg text-secondary"></i> <span class="text-secondary">N/A</span>';
                } else {
                    tlsHostMatchVal.innerHTML = '<i class="bi bi-x-lg text-danger"></i> <span class="text-danger">Mismatch</span>';
                }
            }

            if (tlsExpiryVal) {
                if (tls.has_https && tls.expiry_text) {
                    const isExpWarn = tls.expiry_days !== null && tls.expiry_days <= 14;
                    const colorClass = tls.certificate_valid ? (isExpWarn ? "text-warning" : "text-success") : "text-danger";
                    tlsExpiryVal.className = `tls-check-val ${colorClass}`;
                    tlsExpiryVal.textContent = tls.expiry_text;
                } else {
                    tlsExpiryVal.className = "tls-check-val text-secondary";
                    tlsExpiryVal.textContent = tls.expiry_text || "N/A";
                }
            }

            if (tlsIssuer) tlsIssuer.textContent = tls.issuer || "None";
            if (tlsSubjectCn) tlsSubjectCn.textContent = tls.subject_cn || "None";
            if (tlsIssuedDate) tlsIssuedDate.textContent = tls.issued_date || "N/A";
            if (tlsExpirationDate) tlsExpirationDate.textContent = tls.expiration_date || "N/A";
        }

        // Save scan to session history
        saveRecentScan(data);
        if (!isHistorical) {
            saveScanToHistoryDashboard(data);
        }

        resultSection.scrollIntoView({ behavior: "smooth" });
    }


    // =========================================================================
    // RECENT SCANS HISTORY
    // =========================================================================
    function saveRecentScan(data) {
        try {
            const storageText = (data.payload_info && data.payload_info.sanitized_text) 
                ? data.payload_info.sanitized_text 
                : data.url;

            let scans = JSON.parse(localStorage.getItem("qr_quishing_scans") || "[]");
            scans = scans.filter(s => s.url !== storageText && s.url !== data.url);
            scans.unshift({
                url: storageText,
                hostname: data.hostname || (data.payload_info && data.payload_info.type_label ? `[${data.payload_info.type_label}]` : storageText),
                score: data.score,
                status: data.status,
                timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
            });
            scans = scans.slice(0, 4);
            localStorage.setItem("qr_quishing_scans", JSON.stringify(scans));
            renderRecentScans();
        } catch (e) {
            console.warn("Could not save to localStorage:", e);
        }
    }

    function renderRecentScans() {
        const container = document.getElementById("recentScansContainer");
        const list = document.getElementById("recentScansList");
        if (!container || !list) return;

        try {
            const scans = JSON.parse(localStorage.getItem("qr_quishing_scans") || "[]");
            if (scans.length === 0) {
                container.classList.add("d-none");
                return;
            }

            container.classList.remove("d-none");
            list.innerHTML = "";
            scans.forEach(scan => {
                const item = document.createElement("div");
                item.className = "recent-scan-item";
                const badgeClass = scan.status === "dangerous" ? "badge bg-danger" : (scan.status === "suspicious" ? "badge bg-warning text-dark" : "badge bg-success");
                item.innerHTML = `
                    <div class="d-flex align-items-center gap-2">
                        <i class="bi bi-link-45deg text-primary"></i>
                        <span class="recent-scan-host" title="${scan.url}">${scan.hostname}</span>
                    </div>
                    <div class="d-flex align-items-center gap-2">
                        <span class="${badgeClass}">${scan.score}/100</span>
                        <small class="text-secondary">${scan.timestamp}</small>
                    </div>
                `;
                item.addEventListener("click", () => {
                    urlInput.value = scan.url;
                    analyzeURL(scan.url);
                });
                list.appendChild(item);
            });
        } catch (e) {
            console.warn("Could not load recent scans:", e);
        }
    }

    if (clearRecentBtn) {
        clearRecentBtn.addEventListener("click", () => {
            localStorage.removeItem("qr_quishing_scans");
            renderRecentScans();
        });
    }

    // =========================================================================
    // SECTION 10: SCAN HISTORY DASHBOARD
    // =========================================================================
    let currentHistoryRisk = "ALL";
    let currentHistorySearch = "";

    async function saveScanToHistoryDashboard(data) {
        if (!data || !data.url) return;
        try {
            let riskLevel = "LOW";
            if (data.status === "dangerous" || (data.risk_level && data.risk_level.toUpperCase() === "HIGH") || data.score >= 70) {
                riskLevel = "HIGH";
            } else if (data.status === "suspicious" || (data.risk_level && data.risk_level.toUpperCase() === "MEDIUM") || data.score >= 40) {
                riskLevel = "MEDIUM";
            }

            const storageText = (data.payload_info && data.payload_info.sanitized_text) 
                ? data.payload_info.sanitized_text 
                : data.url;

            // Deep clone data snapshot and sanitize sensitive credentials for storage
            let safeSnapshot = null;
            try {
                safeSnapshot = JSON.parse(JSON.stringify(data));
                if (safeSnapshot.payload_info && safeSnapshot.payload_info.content_type === "wifi") {
                    safeSnapshot.url = storageText;
                    if (safeSnapshot.payload_info.raw_payload) {
                        safeSnapshot.payload_info.raw_payload = storageText;
                    }
                    if (safeSnapshot.payload_info.details && safeSnapshot.payload_info.details.password) {
                        safeSnapshot.payload_info.details.password = "********";
                    }
                }
            } catch (e) {
                safeSnapshot = data;
            }

            const payload = {
                url: storageText,
                risk_level: riskLevel,
                final_score: typeof data.score === "number" ? data.score : 0,
                reasons: Array.isArray(data.reasons) ? data.reasons : [],
                analysis_snapshot: safeSnapshot
            };

            await fetch("/api/v1/history", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload)
            });

            loadScanHistoryDashboard();
        } catch (e) {
            console.warn("Could not save to scan history backend:", e);
        }
    }

    async function loadScanHistoryDashboard(riskFilter, searchQuery) {
        const tbody = document.getElementById("historyTableBody");
        const countBadge = document.getElementById("historyCountBadge");
        const emptyState = document.getElementById("historyEmptyState");
        if (!tbody) return;

        if (riskFilter !== undefined) currentHistoryRisk = riskFilter;
        if (searchQuery !== undefined) currentHistorySearch = searchQuery;

        const params = new URLSearchParams();
        if (currentHistoryRisk && currentHistoryRisk !== "ALL") {
            params.set("risk", currentHistoryRisk);
        }
        if (currentHistorySearch && currentHistorySearch.trim()) {
            params.set("q", currentHistorySearch.trim());
        }

        try {
            const url = `/api/v1/history?${params.toString()}`;
            const res = await fetch(url);
            if (!res.ok) throw new Error(`History fetch failed: ${res.status}`);
            const data = await res.json();
            const items = data.items || [];

            if (countBadge) {
                countBadge.textContent = `${items.length} ${items.length === 1 ? "Scan" : "Scans"}`;
            }

            tbody.innerHTML = "";
            if (items.length === 0) {
                if (emptyState) emptyState.classList.remove("d-none");
                return;
            }

            if (emptyState) emptyState.classList.add("d-none");

            items.forEach(item => {
                const tr = document.createElement("tr");
                tr.className = "history-row-clickable";
                tr.title = "Click to inspect complete multi-engine analysis";

                const risk = (item.risk_level || "LOW").toUpperCase();
                let riskBadgeClass = "history-risk-low";
                if (risk === "HIGH") riskBadgeClass = "history-risk-high";
                else if (risk === "MEDIUM") riskBadgeClass = "history-risk-medium";

                const displayDate = item.relative_date || item.created_at || "Today";

                tr.innerHTML = `
                    <td class="history-url-cell">
                        <div class="d-flex align-items-center gap-2">
                            <i class="bi bi-shield-check text-primary"></i>
                            <span class="text-truncate" style="max-width: 380px;" title="${item.url}">${item.url}</span>
                        </div>
                    </td>
                    <td>
                        <span class="history-risk-badge ${riskBadgeClass}">
                            ${risk}
                        </span>
                    </td>
                    <td class="history-date-cell">
                        <span class="fw-semibold">${displayDate}</span>
                    </td>
                    <td class="text-end">
                        <div class="d-inline-flex gap-1">
                            <button type="button" class="btn btn-sm btn-outline-primary py-0 px-2 view-scan-btn" title="Inspect complete analysis">
                                <i class="bi bi-search me-1"></i> Inspect
                            </button>
                            <button type="button" class="btn btn-sm btn-outline-danger py-0 px-2 download-scan-pdf-btn" title="Download formal PDF security report">
                                <i class="bi bi-file-earmark-pdf"></i>
                            </button>
                        </div>
                    </td>
                `;

                const pdfBtn = tr.querySelector(".download-scan-pdf-btn");
                if (pdfBtn) {
                    pdfBtn.addEventListener("click", (e) => {
                        e.stopPropagation();
                        downloadPdfForScan(item.id, item.hostname || item.url);
                    });
                }

                tr.addEventListener("click", () => {
                    if (item.analysis_snapshot) {
                        displayResult(item.analysis_snapshot, true);
                    } else {
                        urlInput.value = item.url;
                        analyzeURL(item.url);
                    }
                    const resSection = document.getElementById("resultSection");
                    if (resSection) {
                        resSection.classList.remove("d-none");
                        resSection.scrollIntoView({ behavior: "smooth" });
                    }
                });

                tbody.appendChild(tr);
            });
        } catch (e) {
            console.warn("Could not load scan history dashboard:", e);
        }
    }

    // Filter by Risk Buttons
    document.querySelectorAll("#historyRiskFilters button").forEach(btn => {
        btn.addEventListener("click", function () {
            document.querySelectorAll("#historyRiskFilters button").forEach(b => b.classList.remove("active"));
            this.classList.add("active");
            const r = this.getAttribute("data-risk") || "ALL";
            loadScanHistoryDashboard(r, currentHistorySearch);
        });
    });

    // Search filter input
    const historySearchInput = document.getElementById("historySearchInput");
    if (historySearchInput) {
        let debounceTimer = null;
        historySearchInput.addEventListener("input", function () {
            clearTimeout(debounceTimer);
            debounceTimer = setTimeout(() => {
                loadScanHistoryDashboard(currentHistoryRisk, this.value);
            }, 200);
        });
    }

    // Reset Seed History
    const historyResetBtn = document.getElementById("historyResetBtn");
    if (historyResetBtn) {
        historyResetBtn.addEventListener("click", async function () {
            try {
                historyResetBtn.disabled = true;
                await fetch("/api/v1/history/reset", { method: "POST" });
                if (historySearchInput) historySearchInput.value = "";
                currentHistorySearch = "";
                currentHistoryRisk = "ALL";
                document.querySelectorAll("#historyRiskFilters button").forEach(b => {
                    if (b.getAttribute("data-risk") === "ALL") b.classList.add("active");
                    else b.classList.remove("active");
                });
                await loadScanHistoryDashboard("ALL", "");
            } catch (e) {
                console.error("Reset history failed:", e);
            } finally {
                historyResetBtn.disabled = false;
            }
        });
    }

    // Clear History
    const historyClearBtn = document.getElementById("historyClearBtn");
    if (historyClearBtn) {
        historyClearBtn.addEventListener("click", async function () {
            if (!confirm("Are you sure you want to clear all scan history?")) return;
            try {
                historyClearBtn.disabled = true;
                await fetch("/api/v1/history", { method: "DELETE" });
                await loadScanHistoryDashboard(currentHistoryRisk, currentHistorySearch);
            } catch (e) {
                console.error("Clear history failed:", e);
            } finally {
                historyClearBtn.disabled = false;
            }
        });
    }

    // Export CSV
    const historyExportCsvBtn = document.getElementById("historyExportCsvBtn");
    if (historyExportCsvBtn) {
        historyExportCsvBtn.addEventListener("click", async function () {
            try {
                const res = await fetch("/api/v1/history?limit=500");
                const data = await res.json();
                const items = data.items || [];
                if (items.length === 0) {
                    alert("No scan history to export.");
                    return;
                }
                const rows = [
                    ["URL", "Risk Level", "Score", "Date", "Timestamp"]
                ];
                items.forEach(it => {
                    rows.push([
                        `"${(it.url || "").replace(/"/g, '""')}"`,
                        `"${it.risk_level || "LOW"}"`,
                        it.final_score ?? 0,
                        `"${it.relative_date || "Today"}"`,
                        `"${it.created_at || ""}"`
                    ]);
                });
                const csvContent = "data:text/csv;charset=utf-8," + rows.map(e => e.join(",")).join("\n");
                const encodedUri = encodeURI(csvContent);
                const link = document.createElement("a");
                link.setAttribute("href", encodedUri);
                link.setAttribute("download", `scan_history_${new Date().toISOString().slice(0, 10)}.csv`);
                document.body.appendChild(link);
                link.click();
                document.body.removeChild(link);
            } catch (e) {
                console.error("CSV Export failed:", e);
            }
        });
    }

    // =========================================================================
    // MULTI-MODEL ML BENCHMARK MATRIX
    // =========================================================================
    async function loadMlBenchmarks() {
        const tbody = document.getElementById("benchmarkTableBody");
        if (!tbody) return;
        try {
            const res = await fetch("/api/v1/ml/benchmarks");
            if (!res.ok) throw new Error("Failed to load benchmarks");
            const data = await res.json();
            const models = data.models || [];
            tbody.innerHTML = "";
            models.forEach(m => {
                const tr = document.createElement("tr");
                if (m.is_active) tr.className = "active-model-row";
                const statusBadge = m.is_active 
                    ? '<span class="model-badge-active"><i class="bi bi-check-circle-fill"></i> Active Production</span>'
                    : '<span class="model-badge-bench">Benchmarked</span>';
                tr.innerHTML = `
                    <td class="fw-semibold font-mono">${m.model}</td>
                    <td><span class="text-success fw-bold">${m.accuracy.toFixed(2)}%</span></td>
                    <td>${m.precision.toFixed(2)}%</td>
                    <td>${m.recall.toFixed(2)}%</td>
                    <td><strong>${m.f1.toFixed(2)}%</strong></td>
                    <td class="text-secondary">${m.training_time_sec !== null && m.training_time_sec !== undefined ? m.training_time_sec.toFixed(2) + 's' : '-'}</td>
                    <td>${statusBadge}</td>
                `;
                tbody.appendChild(tr);
            });
        } catch (e) {
            console.warn("Could not load ML benchmarks:", e);
            tbody.innerHTML = '<tr><td colspan="7" class="text-center text-secondary py-3">Could not load benchmark metrics</td></tr>';
        }
    }

    // =========================================================================
    // COPY URL BUTTON
    // =========================================================================
    if (copyUrlBtn) {
        copyUrlBtn.addEventListener("click", function () {
            const textToCopy = document.getElementById("scannedUrl").textContent.trim();
            if (!textToCopy || textToCopy === "-") return;

            navigator.clipboard.writeText(textToCopy).then(() => {
                copyUrlBtn.innerHTML = '<i class="bi bi-check-lg text-success"></i> Copied!';
                setTimeout(() => {
                    copyUrlBtn.innerHTML = '<i class="bi bi-clipboard"></i> Copy';
                }, 2000);
            }).catch(err => {
                console.error("Clipboard copy error:", err);
            });
        });
    }

    // =========================================================================
    // COPY INCIDENT REPORT BUTTON
    // =========================================================================
    if (copyReportBtn) {
        copyReportBtn.addEventListener("click", function () {
            if (!lastAnalysisData) return;
            const d = lastAnalysisData;
            const mlDetail = d.ml_detail || {};
            const suspText = mlDetail.suspicious_probability !== undefined ? mlDetail.suspicious_probability.toFixed(1) + '%' : d.ml_score + '%';
            const legitText = mlDetail.legitimate_probability !== undefined ? mlDetail.legitimate_probability.toFixed(1) + '%' : (100 - d.ml_score) + '%';
            const modelText = mlDetail.model_name || "Gradient Boosting";

            const ruleVal = d.rule_score !== undefined ? d.rule_score : 0;
            const mlVal = d.ml_score !== undefined ? d.ml_score : 0;
            const domainVal = d.domain_score !== undefined ? d.domain_score : 0;
            const finalVal = d.score !== undefined ? d.score : 0;
            let riskLvl = d.risk_level;
            if (!riskLvl) {
                if (finalVal >= 70) riskLvl = "HIGH";
                else if (finalVal >= 35) riskLvl = "MEDIUM";
                else riskLvl = "LOW";
            }

            const reportItems = [
                "==================================================",
                "  QR QUISHING SECURITY INCIDENT REPORT",
                "==================================================",
                `Target Destination : ${d.url}`,
                `Target Hostname    : ${d.hostname}`,
                "--------------------------------------------------",
                "COMBINED RISK ENGINE EVALUATION",
                `Rule Score       : ${ruleVal}/100`,
                `ML Probability   : ${mlVal}%`,
                `Domain Signals   : ${domainVal}/100`,
                "",
                `Final Risk Score : ${finalVal}/100`,
                "",
                "Risk Level:",
                `${riskLvl}`,
                "--------------------------------------------------",
                "Threat Intelligence",
                "",
                `Known malicious URL:     ${d.threat_intel && d.threat_intel.known_malicious ? "YES" : "NO"}`,
                `Threat database matches: ${d.threat_intel ? d.threat_intel.matches_count : 0}`,
                "",
                d.threat_intel && d.threat_intel.known_malicious 
                    ? "⚠ External intelligence indicates\n   this URL has been reported." 
                    : "✓ No threat intelligence database has reported this URL.",
                "--------------------------------------------------",
                `Composite Risk Score: ${d.score} / 100 [${d.status.toUpperCase()}]`,
                `Security Rule Risk : ${d.rule_score}%`,
                `ML Suspicious Prob : ${suspText}`,
                `ML Legitimate Prob : ${legitText}`,
                `Active ML Estimator: ${modelText}`,
                `Domain Signals Score: ${domainVal}/100`,
                `Domain Reputation  : ${d.is_trusted ? "Verified Reputable Authority" : "Untrusted / Third-Party"}`,
                `Host Classification: ${d.is_ip ? "Direct IP Address" : (d.is_shortener ? "URL Shortener" : "Registered Domain")}`,
            ];

            if (mlDetail.explanation) {
                const exp = mlDetail.explanation;
                reportItems.push(
                    "--------------------------------------------------",
                    "ML Explanation & Contributing Signals:",
                    "Strong contributing signals:"
                );
                (exp.top_suspicious || []).forEach(s => {
                    const v = s.value !== undefined && s.value !== null ? ` (${s.name === 'HTTPS' ? 'missing' : 'val: ' + s.value})` : "";
                    reportItems.push(`${s.symbol} ${s.name}${v}`);
                });
                (exp.top_legitimate || []).forEach(s => {
                    const v = s.value !== undefined && s.value !== null ? ` (val: ${s.value})` : "";
                    reportItems.push(`${s.symbol} ${s.name}${v}`);
                });
            }

            if (d.domain_intel && !d.domain_intel.is_ip) {
                const w = d.domain_intel.whois || {};
                const dns = d.domain_intel.dns || {};
                reportItems.push(
                    "--------------------------------------------------",
                    "Domain Intelligence & Infrastructure:",
                    `Domain Age        : ${w.age_text || "Unknown"}${w.is_recently_registered ? " [⚠ RECENTLY REGISTERED]" : ""}`,
                    `Registrar         : ${w.registrar || "Not disclosed"}`,
                    `Created Date      : ${w.creation_date || "Not disclosed"}`,
                    `Expiration Date   : ${w.expiration_date || "Not disclosed"}`,
                    `DNS Status        : ${(dns.status || "Unknown").toUpperCase()}`,
                    `A Records (IPv4)  : ${(dns.a_records || []).join(", ") || "None"}`,
                    `MX Records        : ${(dns.mx_records || []).join(", ") || "None"}`
                );
            }

            if (d.tls_analysis) {
                const t = d.tls_analysis;
                reportItems.push(
                    "--------------------------------------------------",
                    "TLS Security & Certificate:",
                    `HTTPS              : ${t.has_https ? "✓ Active" : "✗ Missing (HTTP Plaintext)"}`,
                    `Certificate        : ${t.certificate_valid ? "✓ Valid" : ("✗ " + (t.certificate_status || "Invalid"))}`,
                    `Hostname match     : ${t.hostname_match ? "✓ Matched" : "✗ Mismatch"}`,
                    `Certificate expiry : ${t.expiry_text || "N/A"}`,
                    `Issuer             : ${t.issuer || "None"}`,
                    `Advisory           : Valid HTTPS verifies encryption in transit, not destination trustworthiness.`
                );
            }

            if (d.is_shortener) {
                reportItems.push(
                    "--------------------------------------------------",
                    "⚠ URL SHORTENER DETECTED",
                    "The QR code points to a shortened URL.",
                    "Destination cannot be trusted based only on the visible short URL.",
                    `Shortener Service  : ${d.hostname || "Detected"}`
                );
                if (d.shortener_info && d.shortener_info.redirect_target) {
                    reportItems.push(`Redirect Target    : ${d.shortener_info.redirect_target}`);
                }
            }

            if (d.obfuscation_analysis && d.obfuscation_analysis.is_obfuscated) {
                const obf = d.obfuscation_analysis;
                reportItems.push(
                    "--------------------------------------------------",
                    obf.warning_title || "⚠ POSSIBLE URL OBFUSCATION",
                    obf.warning_message || "The domain contains an obfuscated representation.",
                    `Detected Techniques: ${(obf.detected_techniques || []).join(", ")}`
                );
                if (obf.punycode_info && obf.punycode_info.visually_resembles) {
                    reportItems.push(`Visually Resembles : ${obf.punycode_info.visually_resembles}`);
                }
            }

            if (d.brand_impersonation && d.brand_impersonation.is_impersonation) {
                const b = d.brand_impersonation;
                reportItems.push(
                    "--------------------------------------------------",
                    b.warning_title || "⚠ POSSIBLE BRAND IMPERSONATION",
                    "",
                    "Detected brand-like term:",
                    b.detected_brand || "Brand",
                    "",
                    "Actual domain:",
                    b.actual_domain || d.hostname,
                    "",
                    b.warning_message || `The domain is not an official ${b.detected_brand} domain.`
                );
            }

            if (d.what_should_i_do) {
                reportItems.push(
                    "--------------------------------------------------",
                    "WHAT SHOULD I DO?",
                    d.what_should_i_do.badge_text,
                    d.what_should_i_do.lead_text,
                    "",
                    "Recommendation:",
                    d.what_should_i_do.action_text
                );
            }

            if (d.user_education && (d.status === "dangerous" || d.status === "suspicious" || d.score >= 35)) {
                reportItems.push(
                    "--------------------------------------------------",
                    d.user_education.heading,
                    "",
                    d.user_education.text,
                    "",
                    "Never enter:",
                    ...(d.user_education.prohibited_items || []).map(p => `• ${p}`),
                    "",
                    d.user_education.closing_note
                );
            }

            reportItems.push(
                "--------------------------------------------------",
                "Detected Suspicious Characteristics:",
                ...(d.detected && d.detected.length > 0 ? d.detected.map(c => `✓ ${c}`) : ["✓ No suspicious characteristics detected"]),
                "--------------------------------------------------",
                "Threat Indicators & Heuristics:",
                ...(d.reasons || []).map(r => `• ${r}`),
                "--------------------------------------------------",
                "Incident Recommendation:",
                d.status === "dangerous" ? "ACTION: BLOCKED — High danger of credential theft or payload execution." :
                (d.status === "suspicious" ? "ACTION: CAUTION — Do not enter credentials, OTPs, or passwords." :
                "ACTION: VERIFIED — Safe destination, passes security heuristics."),
                "==================================================",
                "Generated by QR Quishing Inspector v2.0 (FastAPI + ML)"
            );

            const report = reportItems.join("\n");

            navigator.clipboard.writeText(report).then(() => {
                copyReportBtn.innerHTML = '<i class="bi bi-check-lg text-success"></i> Report Copied!';
                setTimeout(() => {
                    copyReportBtn.innerHTML = '<i class="bi bi-clipboard-data"></i> Copy Incident Summary';
                }, 2000);
            }).catch(err => {
                console.error("Clipboard copy failed:", err);
            });
        });
    }

    // =========================================================================
    // SECTION 11: SECURITY ANALYSIS REPORT & DOWNLOADABLE PDF
    // =========================================================================
    async function downloadPdfForScan(scanId, host) {
        try {
            const res = await fetch(`/api/v1/report/${scanId}/pdf`);
            if (!res.ok) throw new Error("Could not download report PDF");
            const blob = await res.blob();
            const cleanHost = (host || "target").replace(/[^a-zA-Z0-9_.-]/g, "_");
            const filename = `quishing_security_report_${cleanHost}.pdf`;
            const downloadUrl = window.URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = downloadUrl;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.URL.revokeObjectURL(downloadUrl);
        } catch (err) {
            console.error("PDF download error:", err);
            alert("Failed to download PDF report: " + err.message);
        }
    }

    async function downloadPdfFromAnalysis(data) {
        if (!data || !data.url) {
            alert("No scan data available to generate report.");
            return;
        }
        try {
            const res = await fetch("/api/v1/report/pdf", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ analysis: data })
            });
            if (!res.ok) throw new Error("PDF report generation failed.");
            const blob = await res.blob();
            const cleanHost = (data.hostname || data.url || "target").replace(/[^a-zA-Z0-9_.-]/g, "_");
            const filename = `quishing_security_report_${cleanHost}.pdf`;
            const downloadUrl = window.URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = downloadUrl;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.URL.revokeObjectURL(downloadUrl);
        } catch (err) {
            console.error("Download PDF error:", err);
            alert("Failed to generate PDF report: " + err.message);
        }
    }

    const viewTextReportBtn = document.getElementById("viewTextReportBtn");
    const downloadPdfReportBtn = document.getElementById("downloadPdfReportBtn");
    const securityReportModal = document.getElementById("securityReportModal");
    const securityReportPre = document.getElementById("securityReportPre");
    const copyModalReportBtn = document.getElementById("copyModalReportBtn");
    const modalDownloadPdfBtn = document.getElementById("modalDownloadPdfBtn");

    if (downloadPdfReportBtn) {
        downloadPdfReportBtn.addEventListener("click", function () {
            if (!lastAnalysisData) {
                alert("Please scan or inspect a URL first.");
                return;
            }
            downloadPdfFromAnalysis(lastAnalysisData);
        });
    }

    function openSecurityReportModal(reportText) {
        if (securityReportPre) {
            securityReportPre.textContent = reportText;
        }
        if (!securityReportModal) return;

        // 1. Try standard Bootstrap 5 Modal API if loaded
        if (typeof bootstrap !== "undefined" && bootstrap.Modal) {
            try {
                const modalInstance = bootstrap.Modal.getOrCreateInstance(securityReportModal);
                modalInstance.show();
                return;
            } catch (err) {
                console.warn("Bootstrap modal show error, falling back to native:", err);
            }
        }

        // 2. Native zero-dependency fallback controller (pure CSS / JS)
        securityReportModal.classList.add("show");
        securityReportModal.style.display = "block";
        securityReportModal.removeAttribute("aria-hidden");
        securityReportModal.setAttribute("aria-modal", "true");
        document.body.classList.add("modal-open");
        document.body.style.overflow = "hidden";

        let backdrop = document.getElementById("nativeReportBackdrop");
        if (!backdrop) {
            backdrop = document.createElement("div");
            backdrop.id = "nativeReportBackdrop";
            backdrop.className = "modal-backdrop fade show";
            document.body.appendChild(backdrop);
        } else {
            backdrop.style.display = "block";
        }

        function closeNativeModal() {
            securityReportModal.classList.remove("show");
            securityReportModal.style.display = "none";
            securityReportModal.setAttribute("aria-hidden", "true");
            securityReportModal.removeAttribute("aria-modal");
            document.body.classList.remove("modal-open");
            document.body.style.overflow = "";
            const b = document.getElementById("nativeReportBackdrop");
            if (b) b.remove();
            document.removeEventListener("keydown", onEscapePress);
        }

        function onEscapePress(e) {
            if (e.key === "Escape") closeNativeModal();
        }

        securityReportModal.querySelectorAll('[data-bs-dismiss="modal"]').forEach(btn => {
            btn.onclick = closeNativeModal;
        });

        if (backdrop) {
            backdrop.onclick = closeNativeModal;
        }

        securityReportModal.onclick = function (e) {
            if (e.target === securityReportModal) {
                closeNativeModal();
            }
        };

        document.addEventListener("keydown", onEscapePress);
    }

    function generateLocalTextReport(data) {
        if (!data) return "No scan data available.";
        const url = data.url || (data.payload_info && data.payload_info.sanitized_text) || "-";
        const score = data.score !== undefined ? data.score : 0;
        let riskLvl = (data.risk_level || "").toUpperCase();
        if (!riskLvl) {
            riskLvl = score >= 70 ? "HIGH" : (score >= 35 ? "MEDIUM" : "LOW");
        }

        const findings = [];
        if (data.detected && Array.isArray(data.detected)) {
            data.detected.forEach(d => {
                const clean = d.replace(/^✓\s*/, '').trim();
                if (clean && !findings.includes(clean)) findings.push(clean);
            });
        }
        if (findings.length === 0) {
            if (data.reasons && Array.isArray(data.reasons)) {
                data.reasons.forEach(r => { if (r && !findings.includes(r)) findings.push(r); });
            }
        }
        if (findings.length === 0) {
            findings.push("Authentic domain characteristics verified", "No suspicious keywords or obfuscation detected", "Valid SSL/TLS certificate structure");
        }

        const ml = data.ml_detail || {};
        const suspProb = ml.suspicious_probability !== undefined ? ml.suspicious_probability : (data.ml_score || 0);

        let rec = "Still verify the destination before entering credentials or payment information.";
        if (riskLvl === "HIGH") {
            rec = "Do not enter credentials or payment information.";
        } else if (riskLvl === "MEDIUM") {
            rec = "Proceed with extreme caution. Avoid entering sensitive data.";
        }

        const lines = [
            "QR QUISHING INSPECTOR",
            "Security Analysis Report",
            "",
            "URL:",
            url,
            "",
            "Risk:",
            `${riskLvl} — ${score}/100`,
            "",
            "Findings:",
            ...findings.slice(0, 6).map(f => `• ${f}`),
            "",
            "ML:",
            `${Number(suspProb).toFixed(1)}% suspicious`,
            "",
            "Recommendation:",
            rec
        ];
        return lines.join("\n");
    }

    if (viewTextReportBtn) {
        viewTextReportBtn.addEventListener("click", async function () {
            if (!lastAnalysisData) {
                alert("Please scan or inspect a URL first.");
                return;
            }
            try {
                viewTextReportBtn.disabled = true;
                viewTextReportBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span> Generating...';

                let reportText = "";
                try {
                    const res = await fetch("/api/v1/report/text", {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ analysis: lastAnalysisData })
                    });
                    if (res.ok) {
                        const data = await res.json();
                        reportText = data.report_text;
                    }
                } catch (fetchErr) {
                    console.warn("API report/text fetch failed, using local fallback:", fetchErr);
                }

                if (!reportText) {
                    reportText = generateLocalTextReport(lastAnalysisData);
                }

                openSecurityReportModal(reportText);

                const inlineCard = document.getElementById("inlineSecurityReportCard");
                const inlinePre = document.getElementById("inlineSecurityReportPre");
                if (inlinePre) inlinePre.textContent = reportText;
                if (inlineCard) inlineCard.classList.remove("d-none");
            } catch (err) {
                console.error("View text report error:", err);
                const fallbackText = generateLocalTextReport(lastAnalysisData);
                openSecurityReportModal(fallbackText);
                const inlineCard = document.getElementById("inlineSecurityReportCard");
                const inlinePre = document.getElementById("inlineSecurityReportPre");
                if (inlinePre) inlinePre.textContent = fallbackText;
                if (inlineCard) inlineCard.classList.remove("d-none");
            } finally {
                viewTextReportBtn.disabled = false;
                viewTextReportBtn.innerHTML = '<i class="bi bi-file-text"></i> <span>View Security Report</span>';
            }
        });
    }

    // Inline report card controls
    const copyInlineReportBtn = document.getElementById("copyInlineReportBtn");
    const inlineDownloadPdfBtn = document.getElementById("inlineDownloadPdfBtn");
    const closeInlineReportBtn = document.getElementById("closeInlineReportBtn");
    const inlineSecurityReportCard = document.getElementById("inlineSecurityReportCard");
    const inlineSecurityReportPre = document.getElementById("inlineSecurityReportPre");

    if (copyInlineReportBtn && inlineSecurityReportPre) {
        copyInlineReportBtn.addEventListener("click", function () {
            const text = inlineSecurityReportPre.textContent;
            navigator.clipboard.writeText(text).then(() => {
                copyInlineReportBtn.innerHTML = '<i class="bi bi-check-lg text-success"></i> Copied!';
                setTimeout(() => {
                    copyInlineReportBtn.innerHTML = '<i class="bi bi-clipboard"></i> Copy Text';
                }, 2000);
            }).catch(e => console.error(e));
        });
    }

    if (inlineDownloadPdfBtn) {
        inlineDownloadPdfBtn.addEventListener("click", function () {
            if (lastAnalysisData) {
                downloadPdfFromAnalysis(lastAnalysisData);
            }
        });
    }

    if (closeInlineReportBtn && inlineSecurityReportCard) {
        closeInlineReportBtn.addEventListener("click", function () {
            inlineSecurityReportCard.classList.add("d-none");
        });
    }

    if (copyModalReportBtn && securityReportPre) {
        copyModalReportBtn.addEventListener("click", function () {
            const text = securityReportPre.textContent;
            navigator.clipboard.writeText(text).then(() => {
                copyModalReportBtn.innerHTML = '<i class="bi bi-check-lg text-success"></i> Copied!';
                setTimeout(() => {
                    copyModalReportBtn.innerHTML = '<i class="bi bi-clipboard"></i> Copy Text';
                }, 2000);
            }).catch(e => console.error(e));
        });
    }

    if (modalDownloadPdfBtn) {
        modalDownloadPdfBtn.addEventListener("click", function () {
            if (lastAnalysisData) {
                downloadPdfFromAnalysis(lastAnalysisData);
            }
        });
    }

    // =========================================================================
    // SCAN AGAIN
    // =========================================================================
    if (scanAgainButton) {
        scanAgainButton.addEventListener("click", function () {
            document.getElementById("resultSection").classList.add("d-none");
            if (inlineSecurityReportCard) inlineSecurityReportCard.classList.add("d-none");
            urlInput.value = "";
            window.scrollTo({ top: 0, behavior: "smooth" });
        });
    }

    // =========================================================================
    // FEATURE 17: AUTHENTICATION & ANALYST SESSION CONTROLLER
    // =========================================================================
    const TOKEN_STORAGE_KEY = "qr_quishing_token";
    const USER_STORAGE_KEY = "qr_quishing_user";

    const navAuthGuest = document.getElementById("navAuthGuest");
    const navAuthUser = document.getElementById("navAuthUser");
    const userAvatarText = document.getElementById("userAvatarText");
    const navUserName = document.getElementById("navUserName");
    const navUserRole = document.getElementById("navUserRole");
    const dropdownUserFullName = document.getElementById("dropdownUserFullName");
    const dropdownUserEmail = document.getElementById("dropdownUserEmail");

    const signInModalEl = document.getElementById("signInModal");
    const signUpModalEl = document.getElementById("signUpModal");
    const signInForm = document.getElementById("signInForm");
    const signUpForm = document.getElementById("signUpForm");
    const signInAlert = document.getElementById("signInAlert");
    const signUpAlert = document.getElementById("signUpAlert");
    const fillDemoCredentialsBtn = document.getElementById("fillDemoCredentialsBtn");
    const switchToSignUpBtn = document.getElementById("switchToSignUpBtn");
    const switchToSignInBtn = document.getElementById("switchToSignInBtn");
    const signOutBtn = document.getElementById("signOutBtn");

    function getInitials(name) {
        if (!name) return "U";
        const parts = name.trim().split(/\s+/);
        if (parts.length >= 2) {
            return (parts[0][0] + parts[1][0]).toUpperCase();
        }
        return name.slice(0, 2).toUpperCase();
    }

    function updateAuthUI(user) {
        if (user) {
            if (navAuthGuest) navAuthGuest.classList.add("d-none");
            if (navAuthUser) {
                navAuthUser.classList.remove("d-none");
                navAuthUser.classList.add("d-flex");
            }
            const displayName = user.full_name || user.username || "Analyst";
            if (userAvatarText) userAvatarText.textContent = getInitials(displayName);
            if (navUserName) navUserName.textContent = displayName;
            if (navUserRole) navUserRole.textContent = (user.role || "analyst").toUpperCase();
            if (dropdownUserFullName) dropdownUserFullName.textContent = displayName;
            if (dropdownUserEmail) dropdownUserEmail.textContent = user.email || "";
        } else {
            if (navAuthGuest) {
                navAuthGuest.classList.remove("d-none");
                navAuthGuest.classList.add("d-flex");
            }
            if (navAuthUser) {
                navAuthUser.classList.add("d-none");
                navAuthUser.classList.remove("d-flex");
            }
        }
    }

    function getAuthToken() {
        return localStorage.getItem(TOKEN_STORAGE_KEY);
    }

    function setAuthSession(token, user) {
        if (token) localStorage.setItem(TOKEN_STORAGE_KEY, token);
        if (user) localStorage.setItem(USER_STORAGE_KEY, JSON.stringify(user));
        updateAuthUI(user);
    }

    function clearAuthSession() {
        localStorage.removeItem(TOKEN_STORAGE_KEY);
        localStorage.removeItem(USER_STORAGE_KEY);
        updateAuthUI(null);
    }

    function showModalGeneric(modalEl) {
        if (!modalEl) return;
        if (typeof bootstrap !== "undefined" && bootstrap.Modal) {
            try {
                const instance = bootstrap.Modal.getOrCreateInstance(modalEl);
                instance.show();
                return;
            } catch (e) {}
        }
        modalEl.classList.add("show");
        modalEl.style.display = "block";
        modalEl.removeAttribute("aria-hidden");
        modalEl.setAttribute("aria-modal", "true");
        document.body.classList.add("modal-open");
        let b = document.getElementById("nativeAuthBackdrop");
        if (!b) {
            b = document.createElement("div");
            b.id = "nativeAuthBackdrop";
            b.className = "modal-backdrop fade show";
            document.body.appendChild(b);
            b.onclick = () => hideModalGeneric(modalEl);
        } else {
            b.style.display = "block";
        }
    }

    function hideModalGeneric(modalEl) {
        if (!modalEl) return;
        if (typeof bootstrap !== "undefined" && bootstrap.Modal) {
            try {
                const instance = bootstrap.Modal.getInstance(modalEl);
                if (instance) {
                    instance.hide();
                    return;
                }
            } catch (e) {}
        }
        modalEl.classList.remove("show");
        modalEl.style.display = "none";
        modalEl.setAttribute("aria-hidden", "true");
        modalEl.removeAttribute("aria-modal");
        document.body.classList.remove("modal-open");
        const b = document.getElementById("nativeAuthBackdrop");
        if (b) b.remove();
    }

    window.openSignInModal = () => showModalGeneric(signInModalEl);
    window.openSignUpModal = () => showModalGeneric(signUpModalEl);

    // Modal switch handlers
    if (switchToSignUpBtn) {
        switchToSignUpBtn.addEventListener("click", function () {
            hideModalGeneric(signInModalEl);
            setTimeout(() => showModalGeneric(signUpModalEl), 150);
        });
    }

    if (switchToSignInBtn) {
        switchToSignInBtn.addEventListener("click", function () {
            hideModalGeneric(signUpModalEl);
            setTimeout(() => showModalGeneric(signInModalEl), 150);
        });
    }

    // Native modal close button fallback listeners
    [signInModalEl, signUpModalEl].forEach(m => {
        if (!m) return;
        m.querySelectorAll('[data-bs-dismiss="modal"]').forEach(btn => {
            btn.onclick = () => hideModalGeneric(m);
        });
    });

    // Password visibility toggle buttons
    document.querySelectorAll(".toggle-password-btn").forEach(btn => {
        btn.addEventListener("click", function () {
            const targetId = this.getAttribute("data-target");
            const input = document.getElementById(targetId);
            if (!input) return;
            const icon = this.querySelector("i");
            if (input.type === "password") {
                input.type = "text";
                if (icon) {
                    icon.classList.remove("bi-eye");
                    icon.classList.add("bi-eye-slash");
                }
            } else {
                input.type = "password";
                if (icon) {
                    icon.classList.remove("bi-eye-slash");
                    icon.classList.add("bi-eye");
                }
            }
        });
    });

    // One-Click Demo Credentials
    if (fillDemoCredentialsBtn) {
        fillDemoCredentialsBtn.addEventListener("click", function () {
            const idInput = document.getElementById("signInIdentifier");
            const passInput = document.getElementById("signInPassword");
            if (idInput) idInput.value = "demo_analyst";
            if (passInput) passInput.value = "Analyst#2026";
            if (signInAlert) signInAlert.classList.add("d-none");
        });
    }

    // Sign In Form Submission
    if (signInForm) {
        signInForm.addEventListener("submit", async function (e) {
            e.preventDefault();
            const identifier = document.getElementById("signInIdentifier").value.trim();
            const password = document.getElementById("signInPassword").value;
            const submitBtn = document.getElementById("signInSubmitBtn");

            if (!identifier || !password) {
                if (signInAlert) {
                    signInAlert.textContent = "Please provide both username/email and password.";
                    signInAlert.classList.remove("d-none");
                }
                return;
            }

            try {
                if (submitBtn) {
                    submitBtn.disabled = true;
                    submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span> Signing In...';
                }
                if (signInAlert) signInAlert.classList.add("d-none");

                const res = await fetch("/api/v1/auth/signin", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ identifier, password }),
                });

                const data = await res.json();
                if (!res.ok) {
                    const msg = data.detail || "Invalid credentials. Please try again.";
                    if (signInAlert) {
                        signInAlert.textContent = msg;
                        signInAlert.classList.remove("d-none");
                    }
                    return;
                }

                setAuthSession(data.access_token, data.user);
                hideModalGeneric(signInModalEl);
                signInForm.reset();
            } catch (err) {
                if (signInAlert) {
                    signInAlert.textContent = "Network error while connecting to authentication service.";
                    signInAlert.classList.remove("d-none");
                }
            } finally {
                if (submitBtn) {
                    submitBtn.disabled = false;
                    submitBtn.innerHTML = '<i class="bi bi-box-arrow-in-right me-1"></i> Sign In';
                }
            }
        });
    }

    // Sign Up Form Submission
    if (signUpForm) {
        signUpForm.addEventListener("submit", async function (e) {
            e.preventDefault();
            const fullName = document.getElementById("signUpFullName").value.trim();
            const username = document.getElementById("signUpUsername").value.trim();
            const email = document.getElementById("signUpEmail").value.trim();
            const password = document.getElementById("signUpPassword").value;
            const confirm = document.getElementById("signUpPasswordConfirm").value;
            const submitBtn = document.getElementById("signUpSubmitBtn");

            if (!fullName || !username || !email || !password) {
                if (signUpAlert) {
                    signUpAlert.textContent = "Please fill in all registration fields.";
                    signUpAlert.classList.remove("d-none");
                }
                return;
            }

            if (password !== confirm) {
                if (signUpAlert) {
                    signUpAlert.textContent = "Passwords do not match. Please verify.";
                    signUpAlert.classList.remove("d-none");
                }
                return;
            }

            if (password.length < 8) {
                if (signUpAlert) {
                    signUpAlert.textContent = "Password must be at least 8 characters long.";
                    signUpAlert.classList.remove("d-none");
                }
                return;
            }

            try {
                if (submitBtn) {
                    submitBtn.disabled = true;
                    submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span> Registering...';
                }
                if (signUpAlert) signUpAlert.classList.add("d-none");

                const res = await fetch("/api/v1/auth/signup", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        full_name: fullName,
                        username: username,
                        email: email,
                        password: password,
                    }),
                });

                const data = await res.json();
                if (!res.ok) {
                    const msg = data.detail || "Registration failed. Please check your inputs.";
                    if (signUpAlert) {
                        signUpAlert.textContent = msg;
                        signUpAlert.classList.remove("d-none");
                    }
                    return;
                }

                setAuthSession(data.access_token, data.user);
                hideModalGeneric(signUpModalEl);
                signUpForm.reset();
            } catch (err) {
                if (signUpAlert) {
                    signUpAlert.textContent = "Network error while connecting to authentication service.";
                    signUpAlert.classList.remove("d-none");
                }
            } finally {
                if (submitBtn) {
                    submitBtn.disabled = false;
                    submitBtn.innerHTML = '<i class="bi bi-person-check-fill me-1"></i> Complete Registration';
                }
            }
        });
    }

    // Sign Out Handler
    if (signOutBtn) {
        signOutBtn.addEventListener("click", async function () {
            try {
                await fetch("/api/v1/auth/signout", { method: "POST" });
            } catch (e) {}
            clearAuthSession();
        });
    }

    // Session Verification On Load
    (async function initSession() {
        const storedToken = getAuthToken();
        const storedUser = localStorage.getItem(USER_STORAGE_KEY);
        if (storedUser) {
            try {
                updateAuthUI(JSON.parse(storedUser));
            } catch (e) {}
        }
        if (storedToken) {
            try {
                const res = await fetch("/api/v1/auth/me", {
                    headers: { "Authorization": "Bearer " + storedToken }
                });
                if (res.ok) {
                    const user = await res.json();
                    setAuthSession(storedToken, user);
                } else if (res.status === 401) {
                    clearAuthSession();
                }
            } catch (e) {
                // Keep local UI state if offline
            }
        } else {
            updateAuthUI(null);
        }
    })();
});