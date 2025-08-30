/*
 *  This file is part of the GetWVKeys project (https://github.com/GetWVKeys/getwvkeys)
 *  Copyright (C) 2022-2024 Notaghost, Puyodead1 and GetWVKeys contributors
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License as published
 *  by the Free Software Foundation, version 3 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Affero General Public License for more details.
 *
 *  You should have received a copy of the GNU Affero General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(";").shift();
}

async function loadSystemDevices() {
    try {
        const apiKey = getCookie("api_key");
        const response = await fetch("/admin/api-system-devices", {
            method: "GET",
            headers: {
                "X-API-Key": apiKey,
            },
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const data = await response.json();
        displayDevices(data);
        updateStats(data);
    } catch (error) {
        console.error("Error loading system devices:", error);
        document.getElementById("wvd-tbody").innerHTML = '<tr><td colspan="5">Error loading devices</td></tr>';
        document.getElementById("prd-tbody").innerHTML = '<tr><td colspan="5">Error loading devices</td></tr>';
    }
}

function updateStats(data) {
    const wvdCount = data.wvds.length;
    const prdCount = data.prds.length;
    const rotationCount = data.wvds.filter((d) => d.enabled_for_rotation).length + data.prds.filter((d) => d.enabled_for_rotation).length;

    document.getElementById("wvd-count").textContent = wvdCount;
    document.getElementById("prd-count").textContent = prdCount;
    document.getElementById("rotation-count").textContent = rotationCount;
}

function displayDevices(data) {
    displayWVDs(data.wvds);
    displayPRDs(data.prds);
}

function displayWVDs(wvds) {
    const tbody = document.getElementById("wvd-tbody");

    if (wvds.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7">No WVD devices found</td></tr>';
        return;
    }

    tbody.innerHTML = wvds
        .map(
            (device) => `
        <tr>
            <td>${device.id}</td>
            <td>${device.type}</td>
            <td>${device.security_level}</td>
            <td>${device.system_id}</td>
            <td class="scrollable"><code>${device.hash}</code></td>
            <td>
                <span class="rotation-badge ${device.enabled_for_rotation ? "rotation-enabled" : "rotation-disabled"}">
                    ${device.enabled_for_rotation ? "Enabled" : "Disabled"}
                </span>
            </td>
            <td>
                <div class="action-buttons">
                    <button class="btn btn-toggle" onclick="toggleRotation(${device.id}, 'wvd', ${!device.enabled_for_rotation})">
                        ${device.enabled_for_rotation ? "Disable" : "Enable"}
                    </button>
                    <button class="btn btn-delete" onclick="deleteDevice(${device.id}, 'wvd')">
                        Delete
                    </button>
                </div>
            </td>
        </tr>
    `
        )
        .join("");
}

function displayPRDs(prds) {
    const tbody = document.getElementById("prd-tbody");

    if (prds.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6">No PRD devices found</td></tr>';
        return;
    }

    tbody.innerHTML = prds
        .map(
            (device) => `
        <tr>
            <td>${device.id}</td>
            <td>${device.security_level}</td>
            <td class="scrollable"><code>${device.name}</code></td>
            <td class="scrollable"><code>${device.hash}</code></td>
            <td>
                <span class="rotation-badge ${device.enabled_for_rotation ? "rotation-enabled" : "rotation-disabled"}">
                    ${device.enabled_for_rotation ? "Enabled" : "Disabled"}
                </span>
            </td>
            <td>
                <div class="action-buttons">
                    <button class="btn btn-toggle" onclick="toggleRotation(${device.id}, 'prd', ${!device.enabled_for_rotation})">
                        ${device.enabled_for_rotation ? "Disable" : "Enable"}
                    </button>
                    <button class="btn btn-delete" onclick="deleteDevice(${device.id}, 'prd')">
                        Delete
                    </button>
                </div>
            </td>
        </tr>
    `
        )
        .join("");
}

async function toggleRotation(deviceId, deviceType, enable) {
    const action = enable ? "enable" : "disable";

    if (!confirm(`Are you sure you want to ${action} rotation for this ${deviceType.toUpperCase()} device?`)) {
        return;
    }

    try {
        const apiKey = getCookie("api_key");
        const response = await fetch(`/admin/system-devices/${deviceType}/${deviceId}/rotation`, {
            method: "PATCH",
            headers: {
                "Content-Type": "application/json",
                "X-API-Key": apiKey,
            },
            body: JSON.stringify({ enabled: enable }),
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.message || `HTTP ${response.status}`);
        }

        const result = await response.json();
        alert(result.message);
        loadSystemDevices(); // Refresh the table
    } catch (error) {
        console.error("Error toggling rotation:", error);
        alert(`Error: ${error.message}`);
    }
}

async function deleteDevice(deviceId, deviceType) {
    if (!confirm(`Are you sure you want to delete this ${deviceType.toUpperCase()} device? This action cannot be undone.`)) {
        return;
    }

    try {
        const apiKey = getCookie("api_key");
        const response = await fetch(`/admin/system-devices/${deviceType}/${deviceId}`, {
            method: "DELETE",
            headers: {
                "X-API-Key": apiKey,
            },
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.message || `HTTP ${response.status}`);
        }

        const result = await response.json();
        alert(result.message);
        loadSystemDevices(); // Refresh the table
    } catch (error) {
        console.error("Error deleting device:", error);
        alert(`Error: ${error.message}`);
    }
}

// Load devices when page loads
document.addEventListener("DOMContentLoaded", loadSystemDevices);
