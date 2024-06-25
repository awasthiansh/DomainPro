// Wait for the DOM to fully load before executing the script
document.addEventListener("DOMContentLoaded", function() {
    const fetchButton = document.getElementById("fetch-button");

    // Add event listener to the fetch button
    fetchButton.addEventListener("click", function() {
        const domainInput = document.getElementById("domain");
        const domain = domainInput.value.trim();

        // Check if the domain input is empty
        if (!domain) {
            alert("Please enter a domain.");
            return;
        }

        // Call function to fetch information for the given domain
        fetchInformation(domain);
    });

    // Function to fetch Whois, BuiltWith, and Geolocation information
    function fetchInformation(domain) {
        const apiKey = "ENTER_YOUR_API_KEY"; // Replace with your own API key
        const builtWithApiKey = "ENTER_YOUR_API_KEY"; // Replace with your own BuiltWith API key
        
        // API endpoints for Whois, BuiltWith, and Geolocation information
        const whoisUrl = `https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=${apiKey}&domainName=${domain}&outputFormat=JSON`;
        const builtWithUrl = `https://api.builtwith.com/free1/api.json?key=${builtWithApiKey}&LOOKUP=${domain}`;
        const geolocationUrl = `https://ip-geolocation.whoisxmlapi.com/api/v1?apiKey=${apiKey}&domainName=${domain}`;

        // Fetch Whois information
        fetch(whoisUrl)
            .then(response => response.json())
            .then(data => {
                updateWhoisTable(data);
            })
            .catch(error => console.error("Error fetching Whois information:", error));

        // Fetch BuiltWith information
        fetch(builtWithUrl)
            .then(response => response.json())
            .then(data => {
                updateBuiltWithTable(data);
            })
            .catch(error => console.error("Error fetching BuiltWith information:", error));

        // Fetch Geolocation information
        fetch(geolocationUrl)
            .then(response => response.json())
            .then(data => {
                updateGeolocationTable(data);
            })
            .catch(error => console.error("Error fetching Geolocation information:", error));
    }

    // Function to update the Whois table with fetched data
    function updateWhoisTable(data) {
        const whoisTable = document.querySelector("#whois-table tbody");
        whoisTable.innerHTML = "";

        if (data && data.WhoisRecord) {
            const whoisRecord = data.WhoisRecord;
            for (const [key, value] of Object.entries(whoisRecord)) {
                if (typeof value === "object") {
                    for (const [subKey, subValue] of Object.entries(value)) {
                        appendTableRow(whoisTable, `${key} (${subKey})`, subValue);
                    }
                } else {
                    appendTableRow(whoisTable, key, value);
                }
            }
        } else {
            appendTableRow(whoisTable, "Error", "Failed to retrieve Whois information");
        }
    }

    // Function to update the BuiltWith table with fetched data
    function updateBuiltWithTable(data) {
        const builtWithTable = document.querySelector("#builtwith-table tbody");
        builtWithTable.innerHTML = "";

        if (data) {
            for (const [category, details] of Object.entries(data)) {
                if (category === "groups" && Array.isArray(details)) {
                    details.forEach(group => {
                        for (const [key, value] of Object.entries(group)) {
                            appendTableRow(builtWithTable, key, value);
                        }
                    });
                } else if (Array.isArray(details)) {
                    details.forEach(tool => appendTableRow(builtWithTable, category, tool));
                } else {
                    appendTableRow(builtWithTable, category, details);
                }
            }
        } else {
            appendTableRow(builtWithTable, "Error", "Failed to retrieve BuiltWith information");
        }
    }

    // Function to update the Geolocation table with fetched data
    function updateGeolocationTable(data) {
        const geolocationTable = document.querySelector("#geolocation-table tbody");
        geolocationTable.innerHTML = "";

        if (data) {
            for (const [key, value] of Object.entries(data)) {
                appendTableRow(geolocationTable, key, value);
            }
        } else {
            appendTableRow(geolocationTable, "Error", "Failed to retrieve Geolocation information");
        }
    }

    // Helper function to append a row to a table
    function appendTableRow(table, field, value) {
        const row = document.createElement("tr");
        const fieldCell = document.createElement("td");
        fieldCell.textContent = field;
        const valueCell = document.createElement("td");
        valueCell.textContent = value;
        row.appendChild(fieldCell);
        row.appendChild(valueCell);
        table.appendChild(row);
    }
});
