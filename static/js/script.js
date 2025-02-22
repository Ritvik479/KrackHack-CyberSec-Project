document.getElementById("uploadForm").addEventListener("submit", function(event) {
    event.preventDefault();
    
    let formData = new FormData(this);
    document.querySelector(".spinner-border").style.display = "inline-block";
    document.getElementById("scanResult").style.display = "none";
    
    fetch("/scan", {
        method: "POST",
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        document.querySelector(".spinner-border").style.display = "none";
        document.getElementById("scanResult").style.display = "block";
        document.getElementById("resultText").textContent = data.result;
    })
    .catch(error => {
        console.error("Error:", error);
        document.querySelector(".spinner-border").style.display = "none";
    });
});



