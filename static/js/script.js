document.addEventListener("DOMContentLoaded", function () {
    const uploadForm = document.getElementById("uploadForm");
    const loadingSpinner = document.querySelector(".spinner-border");
    const progressBar = document.querySelector(".progress-bar");
    const progressContainer = document.querySelector(".progress");
    const scanResult = document.getElementById("scanResult");
    const darkModeToggle = document.getElementById("darkModeToggle");
    const darkModeIcon = document.getElementById("darkModeIcon");
    const darkModeText = document.getElementById("darkModeText");

    // Check for saved dark mode preference
    if (localStorage.getItem("darkMode") === "enabled") {
        enableDarkMode();
    }

    // Dark Mode Toggle
    darkModeToggle.addEventListener("click", function () {
        if (document.body.classList.contains("dark-mode")) {
            disableDarkMode();
        } else {
            enableDarkMode();
        }
    });

    function enableDarkMode() {
        document.body.classList.add("dark-mode");
        darkModeIcon.textContent = "☀️"; // Change to Sun icon
        darkModeText.textContent = "Light Mode"; // Update text
        darkModeToggle.classList.remove("btn-dark");
        darkModeToggle.classList.add("btn-light");
        localStorage.setItem("darkMode", "enabled"); // Save preference
    }

    function disableDarkMode() {
        document.body.classList.remove("dark-mode");
        darkModeIcon.textContent = "🌙"; // Change to Moon icon
        darkModeText.textContent = "Dark Mode"; // Update text
        darkModeToggle.classList.remove("btn-light");
        darkModeToggle.classList.add("btn-dark");
        localStorage.setItem("darkMode", "disabled"); // Save preference
    }

    // File Upload Form Submission
    uploadForm.addEventListener("submit", function (event) {
        event.preventDefault(); // Prevent default form submission

        scanResult.style.display = "none";
        loadingSpinner.style.display = "inline-block";
        progressContainer.style.display = "block";
        progressBar.style.width = "0%";

        let progress = 0;
        let interval = setInterval(() => {
            progress += 20;
            progressBar.style.width = `${progress}%`;

            if (progress >= 100) {
                clearInterval(interval);
                loadingSpinner.style.display = "none";
                displayScanResult();
            }
        }, 500);
    });

    function displayScanResult() {
        progressContainer.style.display = "none";
        scanResult.style.display = "block";

        let isSafe = Math.random() > 0.3; // 70% chance it's safe

        if (isSafe) {
            scanResult.className = "scan-safe";
            scanResult.textContent = "✅ No malware detected. Your file is safe!";
        } else {
            scanResult.className = "scan-danger";
            scanResult.textContent = "⚠️ Malware detected! Please delete this file.";
        }
    }
});







