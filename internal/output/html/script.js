let selectedTypeFilterValue = new Set();
selectedTypeFilterValue.add("all");
let selectedLayer = "all";

function quickFilterByLayer(DiffID, layerCommand) {
  resetFilterText();
  applyFilters(selectedTypeFilterValue, DiffID);
  selectedDisplay = document.getElementById("layer-filter-selected");
  selectedDisplay.textContent = layerCommand;
}

function showBaseImageLayer(imageID) {
  var detailElementID = "base-image-details-" + imageID;
  var detailsElement = document.getElementById(detailElementID);

  const icon = document.querySelector(
    `#base-image-summary-${imageID} .material-icons`
  ); // Select the icon within the row
  if (detailsElement.style.display !== "block") {
    detailsElement.style.display = "block";
    icon.style.transform = "rotate(90deg)"; // Rotate 90 degrees
    icon.style.transition = "transform 0.2s ease"; // Add smooth transition
  } else {
    detailsElement.style.display = "none";
    icon.style.transform = "rotate(0deg)"; // Rotate back to 0 degrees
    icon.style.transition = "transform 0.2s ease"; // Add smooth transition
  }
}

function showPackageDetails(detailsId) {
  var detailsElement = document.getElementById(
    "table-tr-" + detailsId + "-details"
  );
  var rowElement = document.getElementById("table-tr-" + detailsId);
  const rowCells = rowElement.querySelectorAll("td");
  const icon = document.querySelector(
    `#table-tr-${detailsId} .material-icons`
  ); // Select the icon within the row
  if (detailsElement.style.display !== "block") {
    detailsElement.style.display = "block";
    icon.style.transform = "rotate(90deg)"; // Rotate 90 degrees
    icon.style.transition = "transform 0.2s ease"; // Add smooth transition
  } else {
    detailsElement.style.display = "none";
    icon.style.transform = "rotate(0deg)"; // Rotate back to 0 degrees
    icon.style.transition = "transform 0.2s ease"; // Add smooth transition
  }
}

function openVulnInNewTab(inputString) {
  const osvURL = `https://osv.dev/${inputString}`;
  const tabs = document.getElementById("tabs");
  const tabSwitches = document.getElementById("tab-switch");

  const existingTab = document.getElementById(inputString);
  if (existingTab) {
    openTab(inputString);
    return;
  }

  // Create the new tab div.
  const newTab = document.createElement("div");
  newTab.id = inputString; // Set the ID to the input string
  newTab.className = "tab osv-tab"; // Set the class name

  // Create the iframe element.
  const iframe = document.createElement("iframe");
  iframe.src = osvURL;

  // Create a new tab button
  const newTabButton = document.createElement("div");
  newTabButton.id = inputString + "-button";
  newTabButton.className = "tab-switch-button";
  newTabButton.onclick = function () {
    openTab(inputString);
  };

  // Add <p> and <span> elements to the button
  const newTabTextContainer = document.createElement("div");
  newTabTextContainer.className = "tab-button-text-container";
  const newTabText = document.createElement("p");
  newTabText.textContent = inputString;
  newTabTextContainer.appendChild(newTabText);

  const newTabButtonBorder = document.createElement("div");
  newTabButtonBorder.className = "tab-switch-button-border";
  newTabTextContainer.appendChild(newTabButtonBorder);

  newTabButton.appendChild(newTabTextContainer);

  const closeIcon = document.createElement("span");
  closeIcon.className = "material-icons";
  closeIcon.textContent = "close";
  // Add the onclick function to the close icon
  closeIcon.onclick = function (event) {
    event.stopPropagation(); // Prevent the click from opening the tab
    closeVulnTab(inputString);
  };

  newTabButton.appendChild(closeIcon);

  // Add the iframe to the new tab div.
  newTab.appendChild(iframe);
  // Add the iframe to the container.
  tabs.appendChild(newTab);
  tabSwitches.appendChild(newTabButton);

  openTab(newTab.id);
}

function closeVulnTab(inputString) {
  const tabToRemove = document.getElementById(inputString);
  const buttonToRemove = document.getElementById(inputString + "-button");
  const tabs = document.getElementById("tabs");
  const tabSwitches = document.getElementById("tab-switch");

  if (tabToRemove && buttonToRemove) {
    const nextTabButton =
      buttonToRemove.nextElementSibling ||
      buttonToRemove.previousElementSibling;

    tabs.removeChild(tabToRemove);
    tabSwitches.removeChild(buttonToRemove);

    if (nextTabButton) {
      const nextTabId = nextTabButton.id.replace("-button", "");
      openTab(nextTabId);
    }
  }
}

function openTab(activeTabId) {
  const tabs = document.getElementsByClassName("tab");
  const tabButtons = document.getElementsByClassName("tab-switch-button");
  for (let i = 0; i < tabs.length; i++) {
    if (tabs[i].id === activeTabId) {
      tabs[i].style.display = "block"; // Show the active tab
      tabButtons[i].classList.add("tab-switch-button-selected");
    } else {
      tabs[i].style.display = "none"; // Hide other tabs
      tabButtons[i].classList.remove("tab-switch-button-selected");
    }
  }
}

function hideAllFilterOptions() {
  const containers = document.getElementsByClassName(
    "filter-option-container"
  );
  for (let i = 0; i < containers.length; i++) {
    containers[i].style.display = "none";
  }
}

function toggleFilter(input) {
  targetID = input + "-filter-option-container";
  var optionContainer = document.getElementById(targetID);
  const containers = document.getElementsByClassName(
    "filter-option-container"
  );
  for (let i = 0; i < containers.length; i++) {
    if (containers[i].id === targetID) {
      if (optionContainer.style.display !== "block") {
        optionContainer.style.display = "block";
      } else {
        optionContainer.style.display = "none";
      }
    } else {
      containers[i].style.display = "none";
    }
  }
}

function showAndHideParentSections() {
  const ecosystemContainers = document.querySelectorAll(
    ".ecosystem-container"
  );

  ecosystemContainers.forEach(ecosystemContainer => {
    const sourceContainers =
      ecosystemContainer.querySelectorAll(".source-container");
    let ecosystemHasVisibleSources = false;

    sourceContainers.forEach(sourceContainer => {
      const packageRows = sourceContainer.querySelectorAll(".package-tr");
      let sourceHasVisibleRows = false;

      packageRows.forEach(packageRow => {
        packageDetails = document.getElementById(packageRow.id + "-details");
        const vulnRows = packageDetails.querySelectorAll(".vuln-tr");
        let packageHasVisibleRows = false;
        vulnRows.forEach(vulnRow => {
          if (window.getComputedStyle(vulnRow).display !== "none") {
            packageHasVisibleRows = true;
            return;
          }
        });
        if (packageHasVisibleRows) {
          sourceHasVisibleRows = true;
          packageRow.style.display = "table-row";
          return;
        } else {
          packageRow.style.display = "none";
          packageDetails.style.display = "none";
          const icon = document.querySelector(
            `#${packageRow.id} .material-icons`
          );
          icon.style.transform = "rotate(0deg)"; // Rotate back to 0 degrees
        }
      });

      if (!sourceHasVisibleRows) {
        sourceContainer.style.display = "none";
      } else {
        ecosystemHasVisibleSources = true;
        sourceContainer.style.display = "block";
        return;
      }
    });

    if (!ecosystemHasVisibleSources) {
      ecosystemContainer.style.display = "none";
    } else {
      ecosystemContainer.style.display = "block";
    }
  });
}

function showAllVulns() {
  const vulnRows = document.getElementsByClassName("vuln-tr");
  for (let i = 0; i < vulnRows.length; i++) {
    if (vulnRows[i].classList.contains("uncalled-tr")) {
      vulnRows[i].style.display = "none";
      continue;
    }
    vulnRows[i].style.display = "table-row";
  }

  showAndHideParentSections();
}

function applyFilters(selectedTypeFilterValue, selectedLayerFilterValue) {
  // Show all vulnerabilities and then hide those that do not match the filter requirements.
  showAllVulns();
  applyTypeFilter(selectedTypeFilterValue);
  applyLayerFilter(selectedLayerFilterValue);
  showAndHideParentSections();
}

function applyTypeFilter(selectedValue) {
  updateTypeFilterText(selectedValue);
  selectedAll = selectedValue.has("all");
  selectedProject = selectedValue.has("project");
  selectedOS = selectedValue.has("os");
  selectedUncalled = selectedValue.has("uncalled");
  if (selectedAll) {
    selectedProject = true;
    selectedOS = true;
  }

  const ecosystemElements = document.querySelectorAll(".ecosystem-container");

  ecosystemElements.forEach(ecosystemElement => {
    const vulnElements = ecosystemElement.querySelectorAll(".vuln-tr");
    vulnElements.forEach(vuln => {
      if (vuln.classList.contains("uncalled-tr")) {
        if (selectedUncalled) {
          vuln.style.display = "table-row";
        } else {
          vuln.style.display = "none";
        }
      }
      if (
        (ecosystemElement.classList.contains("os-type") && !selectedOS) ||
        (ecosystemElement.classList.contains("project-type") &&
          !selectedProject)
      ) {
        vuln.style.display = "none";
      }
    });
  });
}

function applyLayerFilter(selectedLayerID) {
  const tableRows = document.querySelectorAll("tr.has-layer-info");
  tableRows.forEach(row => {
    const rowLayerID = row.getAttribute("data-layer");
    if (selectedLayerID !== "all" && rowLayerID !== selectedLayerID) {
      const packageDetails = document.getElementById(row.id + "-details");
      const vulnElements = packageDetails.querySelectorAll(".vuln-tr");
      vulnElements.forEach(vuln => {
        vuln.style.display = "none";
      });
    }
  });
}

function updateTypeFilterText(selectedValue) {
  selectedAll = selectedValue.has("all");
  selectedProject = selectedValue.has("project");
  selectedOS = selectedValue.has("os");
  selectedUncalled = selectedValue.has("uncalled");
  if (selectedAll) {
    selectedProject = true;
    selectedOS = true;
  }

  const typeSelected = document.getElementById("type-filter-selected");
  const selectedVulnCount = document.getElementById("selected-count");

  const allTypeCheckbox = document.getElementById("all-type-checkbox");
  const osTypeCheckbox = document.getElementById("os-type-checkbox");
  const projectTypeCheckbox = document.getElementById(
    "project-type-checkbox"
  );
  const uncalledTypeCheckbox = document.getElementById(
    "uncalled-type-checkbox"
  );

  let selectedText = "";
  let selectedCount = 0;

  if (projectTypeCheckbox && projectTypeCheckbox.checked) {
    selectedText += (selectedText ? ", " : "") + "Project";
    const projectTypeVulnCount = projectTypeCheckbox.getAttribute(
      "data-type-project-count"
    );
    selectedCount += parseInt(projectTypeVulnCount, 10);
  }
  if (osTypeCheckbox && osTypeCheckbox.checked) {
    selectedText += (selectedText ? ", " : "") + "OS";
    const osTypeVulnCount = osTypeCheckbox.getAttribute("data-type-os-count");
    selectedCount += parseInt(osTypeVulnCount, 10);
  }
  if (uncalledTypeCheckbox && uncalledTypeCheckbox.checked) {
    selectedText += (selectedText ? ", " : "") + "Unimportant";
    const uncalledTypeVulnCount = uncalledTypeCheckbox.getAttribute(
      "data-type-uncalled-count"
    );
    selectedCount += parseInt(uncalledTypeVulnCount, 10);
  }

  if (
    allTypeCheckbox &&
    allTypeCheckbox.checked &&
    uncalledTypeCheckbox &&
    !uncalledTypeCheckbox.checked
  ) {
    selectedText = "Default";
  }

  typeSelected.textContent = selectedText;
  selectedVulnCount.textContent = selectedCount;
}

function resetFilterText() {
  const layerSelected = document.getElementById("layer-filter-selected");
  const allLayerCheckedBox = document.getElementById("all-layer-checkbox");
  if (layerSelected) {
    layerSelected.textContent =
      "All layers (" +
      allLayerCheckedBox.getAttribute("data-layer-all-count") +
      ")";
  }

  const typeSelected = document.getElementById("type-filter-selected");
  const selectedVulnCount = document.getElementById("selected-count");
  const allTypeCheckedBox = document.getElementById("all-type-checkbox");
  const uncalledTypeCheckBox = document.getElementById(
    "uncalled-type-checkbox"
  );
  if (allTypeCheckedBox) {
    typeSelected.textContent = "Default";
    selectedVulnCount.textContent = allTypeCheckedBox.getAttribute(
      "data-type-all-count"
    );
    allLayerCheckedBox.checked = true;
    uncalledTypeCheckBox.checked = false;
  } else {
    const projectTypeCheckedBox = document.getElementById(
      "project-type-checkbox"
    );
    projectTypeCheckedBox.checked = true;
    typeSelected.textContent = "Default";
    selectedVulnCount.textContent = projectTypeCheckedBox.getAttribute(
      "data-type-project-count"
    );
    uncalledTypeCheckBox.checked = false;
  }
}

function resetSearchText() {
  const vulnSearchInput = document.getElementById("vuln-search");
  if (vulnSearchInput.value != "") {
    vulnSearchInput.value = "";
    showAllVulns();
  }
}

function resetTypeCheckbox() {
  const allTypeCheckbox = document.getElementById("all-type-checkbox");
  const osTypeCheckbox = document.getElementById("os-type-checkbox");
  const projectTypeCheckbox = document.getElementById(
    "project-type-checkbox"
  );
  const uncalledTypeCheckbox = document.getElementById(
    "uncalled-type-checkbox"
  );

  if (allTypeCheckbox) {
    allTypeCheckbox.checked = true;
    projectTypeCheckbox.checked = true;
    if (osTypeCheckbox) {
      osTypeCheckbox.checked = true;
    }
    uncalledTypeCheckbox.checked = false;
  }
}

document.addEventListener("DOMContentLoaded", function () {
  resetFilterText();
  showAndHideParentSections();

  // Implement filter for vulnerability types
  const typeFilterOptions = document.getElementById(
    "type-filter-option-container"
  );

  typeFilterOptions.addEventListener("change", function () {
    resetSearchText();
    const changedElement = event.target;
    const allTypesCheckbox = document.getElementById("all-type-checkbox");
    const projectCheckbox = document.getElementById("project-type-checkbox"); // Project vulnerabilities
    const osCheckbox = document.getElementById("os-type-checkbox"); // OS vulnerabilities
    const uncalledCheckbox = document.getElementById(
      "uncalled-type-checkbox"
    ); // OS vulnerabilities
    selectedTypeFilterValue.clear();

    if (allTypesCheckbox != null) {
      if (changedElement == allTypesCheckbox) {
        osCheckbox.checked = allTypesCheckbox.checked;
        projectCheckbox.checked = allTypesCheckbox.checked;
        if (allTypesCheckbox.checked === true) {
          selectedTypeFilterValue.add("all");
        }
      }
      if (osCheckbox.checked === false || projectCheckbox.checked === false) {
        allTypesCheckbox.checked = false;
      }

      if (osCheckbox.checked) {
        selectedTypeFilterValue.add("os");
      }
    }

    if (projectCheckbox.checked) {
      selectedTypeFilterValue.add("project");
    }

    if (uncalledCheckbox.checked) {
      selectedTypeFilterValue.add("uncalled");
    }

    applyFilters(selectedTypeFilterValue, selectedLayer);
  });

  // Implement layer filter
  const layerFilterOptionsContainer = document.getElementById(
    "layer-filter-option-container"
  );

  if (layerFilterOptionsContainer) {
    layerFilterOptionsContainer.addEventListener("click", event => {
      const clickedOption = event.target.closest(".layer-filter-option");
      if (clickedOption) {
        resetSearchText();
        selectedLayer = clickedOption.getAttribute("data-layer-hash");
        selectedDisplay = document.getElementById("layer-filter-selected");
        layerCommand = clickedOption.querySelector("p:first-child");
        selectedDisplay.textContent = layerCommand.textContent;

        hideAllFilterOptions();
        applyFilters(selectedTypeFilterValue, selectedLayer);
      }
    });
  }

  // Hide filter options when clicking other parts
  const filterSection = document.getElementById("filter-section");

  document.addEventListener("click", event => {
    if (!filterSection.contains(event.target)) {
      hideAllFilterOptions();
    }
  });

  // Search bar
  const vulnSearchInput = document.getElementById("vuln-search");
  vulnSearchInput.addEventListener("keyup", event => {
    resetFilterText();
    selectedTypeFilterValue.clear();
    selectedTypeFilterValue.add("all");
    selectedLayer = "all";
    resetTypeCheckbox();

    const searchTerm = vulnSearchInput.value.trim().toLowerCase();

    const vulnRows = document.querySelectorAll("[data-vuln-id]");

    if (searchTerm === "") {
      showAllVulns();
      return;
    }

    vulnRows.forEach(row => {
      const vulnID = row.getAttribute("data-vuln-id").toLowerCase();

      if (vulnID.includes(searchTerm)) {
        row.style.display = "table-row";
      } else {
        row.style.display = "none";
      }
    });
    showAndHideParentSections();
  });
});
