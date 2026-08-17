document.addEventListener("DOMContentLoaded", function () {

    console.log("QR Quishing Inspector JavaScript loaded.");

    const video = document.getElementById("video");
    const canvas = document.getElementById("canvas");

    const startCameraButton =
        document.getElementById("startCamera");

    const analyzeButton =
        document.getElementById("analyzeButton");

    const scanAgainButton =
        document.getElementById("scanAgain");

    const urlInput =
        document.getElementById("urlInput");

    const cameraMessage =
        document.getElementById("cameraMessage");


    if (!video ||
        !canvas ||
        !startCameraButton ||
        !analyzeButton ||
        !urlInput) {

        console.error(
            "Required HTML elements were not found."
        );

        return;
    }


    const canvasContext =
        canvas.getContext("2d");


    let cameraStream = null;
    let scanning = false;


    // ==========================================
    // START CAMERA
    // ==========================================

    startCameraButton.addEventListener(
        "click",
        startCamera
    );


    async function startCamera() {

        console.log("Start Camera button clicked.");


        if (!navigator.mediaDevices ||
            !navigator.mediaDevices.getUserMedia) {

            alert(
                "Camera is not supported by this browser."
            );

            return;
        }


        try {

            startCameraButton.disabled = true;

            startCameraButton.innerHTML =
                '<span class="spinner-border spinner-border-sm"></span> Starting Camera...';


            cameraStream =
                await navigator.mediaDevices.getUserMedia({

                    video: {
                        facingMode: {
                            ideal: "environment"
                        }
                    },

                    audio: false

                });


            video.srcObject = cameraStream;

            await video.play();


            cameraMessage.style.display = "none";


            startCameraButton.innerHTML =
                '<i class="bi bi-camera-fill"></i> Camera Active';


            scanning = true;

            scanQRCode();


        } catch (error) {

            console.error(
                "Camera error:",
                error
            );


            startCameraButton.disabled = false;


            startCameraButton.innerHTML =
                '<i class="bi bi-camera-fill"></i> Start Camera';


            if (error.name === "NotAllowedError") {

                alert(
                    "Camera permission was denied. Please allow camera access in your browser."
                );

            } else {

                alert(
                    "Unable to start camera: " +
                    error.message
                );
            }

        }

    }


    // ==========================================
    // QR SCANNING
    // ==========================================

    function scanQRCode() {

        if (!scanning) {
            return;
        }


        if (video.readyState >= 2 &&
            video.videoWidth > 0 &&
            video.videoHeight > 0) {


            canvas.width =
                video.videoWidth;

            canvas.height =
                video.videoHeight;


            canvasContext.drawImage(
                video,
                0,
                0,
                canvas.width,
                canvas.height
            );


            const imageData =
                canvasContext.getImageData(
                    0,
                    0,
                    canvas.width,
                    canvas.height
                );


            // Check whether jsQR loaded
            if (typeof jsQR === "undefined") {

                console.error(
                    "jsQR library is not loaded."
                );

                stopCamera();

                alert(
                    "QR scanner library failed to load. Check your internet connection and refresh the page."
                );

                return;
            }


            const code =
                jsQR(
                    imageData.data,
                    imageData.width,
                    imageData.height
                );


            if (code) {

                console.log(
                    "QR Code detected:",
                    code.data
                );


                const qrData =
                    code.data.trim();


                stopCamera();


                urlInput.value =
                    qrData;


                analyzeURL(qrData);


                return;
            }

        }


        requestAnimationFrame(
            scanQRCode
        );

    }


    // ==========================================
    // STOP CAMERA
    // ==========================================

    function stopCamera() {

        scanning = false;


        if (cameraStream) {

            cameraStream
                .getTracks()
                .forEach(function (track) {

                    track.stop();

                });


            cameraStream = null;
        }


        video.srcObject = null;


        startCameraButton.disabled = false;


        startCameraButton.innerHTML =
            '<i class="bi bi-camera-fill"></i> Start Camera';


        cameraMessage.style.display =
            "flex";

    }


    // ==========================================
    // ANALYZE BUTTON
    // ==========================================

    analyzeButton.addEventListener(
        "click",
        function () {

            console.log(
                "Analyze button clicked."
            );


            const url =
                urlInput.value.trim();


            if (!url) {

                alert(
                    "Please enter a URL first."
                );

                return;
            }


            analyzeURL(url);

        }
    );


    // ==========================================
    // ENTER KEY
    // ==========================================

    urlInput.addEventListener(
        "keydown",
        function (event) {

            if (event.key === "Enter") {

                analyzeButton.click();

            }

        }
    );


    // ==========================================
    // ANALYZE URL
    // ==========================================

    async function analyzeURL(url) {

        console.log(
            "Analyzing:",
            url
        );


        analyzeButton.disabled = true;


        analyzeButton.innerHTML =
            '<span class="spinner-border spinner-border-sm"></span> Analyzing...';


        try {

            const response =
                await fetch(
                    "/analyze",
                    {
                        method: "POST",

                        headers: {
                            "Content-Type":
                                "application/json"
                        },

                        body: JSON.stringify({
                            url: url
                        })
                    }
                );


            console.log(
                "Server response:",
                response.status
            );


            const data =
                await response.json();


            console.log(
                "Analysis result:",
                data
            );


            if (!response.ok ||
                !data.success) {

                throw new Error(
                    data.error ||
                    "Analysis failed."
                );

            }


            displayResult(data);


        } catch (error) {

            console.error(
                "Analysis error:",
                error
            );


            alert(
                "Analysis failed: " +
                error.message
            );


        } finally {

            analyzeButton.disabled =
                false;


            analyzeButton.innerHTML =
                '<i class="bi bi-shield-search"></i> Analyze URL';

        }

    }


    // ==========================================
    // DISPLAY RESULT
    // ==========================================

    function displayResult(data) {

        const resultSection =
            document.getElementById(
                "resultSection"
            );


        const resultIcon =
            document.getElementById(
                "resultIcon"
            );


        const resultTitle =
            document.getElementById(
                "resultTitle"
            );


        const resultMessage =
            document.getElementById(
                "resultMessage"
            );


        const resultLabel =
            document.getElementById(
                "resultLabel"
            );


        const riskScore =
            document.getElementById(
                "riskScore"
            );


        const scannedUrl =
            document.getElementById(
                "scannedUrl"
            );


        const mlScore =
            document.getElementById(
                "mlScore"
            );


        const ruleScore =
            document.getElementById(
                "ruleScore"
            );


        const mlProgress =
            document.getElementById(
                "mlProgress"
            );


        const ruleProgress =
            document.getElementById(
                "ruleProgress"
            );


        const reasonsList =
            document.getElementById(
                "reasonsList"
            );


        resultSection.classList.remove(
            "d-none"
        );


        resultTitle.textContent =
            data.title;


        resultMessage.textContent =
            data.message;


        scannedUrl.textContent =
            data.url;


        riskScore.textContent =
            data.score;


        mlScore.textContent =
            data.ml_score + "%";


        ruleScore.textContent =
            data.rule_score + "%";


        mlProgress.style.width =
            data.ml_score + "%";


        ruleProgress.style.width =
            data.rule_score + "%";


        reasonsList.innerHTML = "";


        data.reasons.forEach(
            function (reason) {

                const li =
                    document.createElement(
                        "li"
                    );


                li.textContent =
                    reason;


                reasonsList.appendChild(
                    li
                );

            }
        );


        resultIcon.className =
            "result-icon";


        if (data.status === "dangerous") {

            resultIcon.innerHTML =
                '<i class="bi bi-shield-x"></i>';

            resultIcon.style.color =
                "var(--danger)";

            resultIcon.style.background =
                "rgba(255, 77, 109, 0.1)";

            resultLabel.textContent =
                "HIGH RISK";

            document
                .querySelector(".score-circle")
                .style.borderColor =
                "var(--danger)";

        }


        else if (data.status === "suspicious") {

            resultIcon.innerHTML =
                '<i class="bi bi-shield-exclamation"></i>';

            resultIcon.style.color =
                "var(--warning)";

            resultIcon.style.background =
                "rgba(255, 193, 7, 0.1)";

            resultLabel.textContent =
                "MEDIUM RISK";

            document
                .querySelector(".score-circle")
                .style.borderColor =
                "var(--warning)";

        }


        else {

            resultIcon.innerHTML =
                '<i class="bi bi-shield-check"></i>';

            resultIcon.style.color =
                "var(--safe)";

            resultIcon.style.background =
                "rgba(25, 230, 140, 0.1)";

            resultLabel.textContent =
                "LOW RISK";

            document
                .querySelector(".score-circle")
                .style.borderColor =
                "var(--safe)";
        }


        resultSection.scrollIntoView({
            behavior: "smooth"
        });

    }


    // ==========================================
    // SCAN AGAIN
    // ==========================================

    if (scanAgainButton) {

        scanAgainButton.addEventListener(
            "click",
            function () {

                document
                    .getElementById(
                        "resultSection"
                    )
                    .classList
                    .add("d-none");


                urlInput.value = "";


                window.scrollTo({
                    top: 0,
                    behavior: "smooth"
                });

            }
        );

    }

});