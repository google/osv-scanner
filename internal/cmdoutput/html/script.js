const selectedTypeFilterValue = new Set(["all"]);
let selectedLayer = "all";

function toggleDetails(summaryID) {
  const detailsElementID = `${summaryID}-details`;
  const iconElementID = `${summaryID}-icon`;
  const detailsElement = document.getElementById(detailsElementID);
  const iconElement = document.getElementById(iconElementID);

  detailsElement.classList.toggle("hide-block");
  iconElement.classList.toggle("expanded");
}

function quickFilterByLayer(DiffID, layerCommand) {
  selectedLayer = DiffID;
  applyFilters(selectedTypeFilterValue, selectedLayer);
  const selectedDisplay = document.getElementById("layer-filter-selected");
  selectedDisplay.textContent = layerCommand;
}

function showBaseImageLayer(imageID) {
  const detailElementID = `base-image-details-${imageID}`;
  const detailsElement = document.getElementById(detailElementID);

  const icon = document.querySelector(
    `#base-image-summary-${imageID} .material-icons`
  ); // Select the icon within the row

  const hidBlock = detailsElement.classList.toggle("hide-block");
  icon.classList.toggle("expanded", !hidBlock);
}

function showPackageDetails(detailsId) {
  const detailsElement = document.getElementById(
    `table-tr-${detailsId}-details`
  );
  const icon = document.querySelector(`#table-tr-${detailsId} .material-icons`); // Select the icon within the row

  const hidBlock = detailsElement.classList.toggle("hide-block");
  icon.classList.toggle("expanded", !hidBlock);
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

  // Create a spinner indicating loading status
  const spinner = document.createElement("div");
  spinner.className = "iframe-spinner";

  // Create the iframe element.
  const iframe = document.createElement("iframe");
  iframe.src = osvURL;
  iframe.onload = () => {
    newTab.removeChild(spinner);
  };

  // Create a new tab button
  const newTabButton = document.createElement("div");
  newTabButton.id = `${inputString}-button`;
  newTabButton.className = "tab-switch-button";
  newTabButton.onclick = () => {
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
  closeIcon.onclick = event => {
    event.stopPropagation(); // Prevent the click from opening the tab
    closeVulnTab(inputString);
  };

  newTabButton.appendChild(closeIcon);

  // Add the iframe to the new tab div.
  newTab.appendChild(spinner);
  newTab.appendChild(iframe);
  // Add the iframe to the container.
  tabs.appendChild(newTab);
  tabSwitches.appendChild(newTabButton);

  openTab(newTab.id);
}

function closeVulnTab(inputString) {
  const tabToRemove = document.getElementById(inputString);
  const buttonToRemove = document.getElementById(`${inputString}-button`);
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
  for (let i = 0; i < tabs.length; i += 1) {
    tabs[i].classList.toggle("hide-block", tabs[i].id !== activeTabId);
    tabButtons[i].classList.toggle(
      "tab-switch-button-selected",
      tabs[i].id === activeTabId
    );
  }
}

function hideAllFilterOptions() {
  const containers = document.getElementsByClassName("filter-option-container");

  for (const container of containers) {
    container.classList.add("hide-block");
  }
}

function toggleFilter(input) {
  const targetID = `${input}-filter-option-container`;
  const optionContainer = document.getElementById(targetID);
  const containers = document.getElementsByClassName("filter-option-container");
  for (const loopContainer of containers) {
    if (loopContainer.id === targetID) {
      optionContainer.classList.toggle("hide-block");
    } else {
      loopContainer.classList.add("hide-block");
    }
  }
}

function showAndHideParentSections() {
  const ecosystemContainers = document.querySelectorAll(".ecosystem-container");

  ecosystemContainers.forEach(ecosystemContainer => {
    const sourceContainers =
      ecosystemContainer.querySelectorAll(".source-container");
    let ecosystemHasVisibleSources = false;

    sourceContainers.forEach(sourceContainer => {
      const packageRows = sourceContainer.querySelectorAll(".package-tr");
      let sourceHasVisibleRows = false;

      packageRows.forEach(packageRow => {
        const packageDetails = document.getElementById(
          `${packageRow.id}-details`
        );
        const vulnRows = packageDetails.querySelectorAll(".vuln-tr");
        if (
          Array.from(vulnRows).some(
            row => !row.classList.contains("hide-block")
          )
        ) {
          sourceHasVisibleRows = true;
          packageRow.classList.remove("hide-block");
          return;
        }

        packageRow.classList.add("hide-block");
        packageDetails.classList.add("hide-block");
        const icon = document.querySelector(
          `#${packageRow.id} .material-icons`
        );
        icon.classList.remove("expanded"); // Rotate back to 0 degrees
      });

      sourceContainer.classList.toggle("hide-block", !sourceHasVisibleRows);

      if (sourceHasVisibleRows) {
        ecosystemHasVisibleSources = true;
      }
    });

    ecosystemContainer.classList.toggle(
      "hide-block",
      !ecosystemHasVisibleSources
    );
  });
}

function showAllVulns() {
  const vulnRows = document.getElementsByClassName("vuln-tr");
  for (const row of vulnRows) {
    const isUncalled = row.classList.contains("uncalled-tr");
    row.classList.toggle("hide-block", isUncalled);
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
  updateTypeFilterText();
  const selectedAll = selectedValue.has("all");
  const selectedProject = selectedAll || selectedValue.has("project");
  const selectedOS = selectedAll || selectedValue.has("os");
  const selectedUncalled = selectedValue.has("uncalled");

  const ecosystemElements = document.querySelectorAll(".ecosystem-container");

  ecosystemElements.forEach(ecosystemElement => {
    const vulnElements = ecosystemElement.querySelectorAll(".vuln-tr");
    vulnElements.forEach(vuln => {
      if (vuln.classList.contains("uncalled-tr")) {
        vuln.classList.toggle("hide-block", !selectedUncalled);
      }
      if (
        (ecosystemElement.classList.contains("os-type") && !selectedOS) ||
        (ecosystemElement.classList.contains("project-type") &&
          !selectedProject)
      ) {
        vuln.classList.add("hide-block");
      }
    });
  });
}

function applyLayerFilter(selectedLayerID) {
  const tableRows = document.querySelectorAll("tr.has-layer-info");
  tableRows.forEach(row => {
    const rowLayerID = row.getAttribute("data-layer");
    if (selectedLayerID !== "all" && rowLayerID !== selectedLayerID) {
      const packageDetails = document.getElementById(`${row.id}-details`);
      const vulnElements = packageDetails.querySelectorAll(".vuln-tr");
      vulnElements.forEach(vuln => {
        vuln.classList.add("hide-block");
      });
    }
  });
}

function updateTypeFilterText() {
  const typeSelected = document.getElementById("type-filter-selected");
  const selectedVulnCount = document.getElementById("selected-count");

  const allTypeCheckbox = document.getElementById("all-type-checkbox");
  const osTypeCheckbox = document.getElementById("os-type-checkbox");
  const projectTypeCheckbox = document.getElementById("project-type-checkbox");
  const uncalledTypeCheckbox = document.getElementById(
    "uncalled-type-checkbox"
  );

  let selectedText = "";
  let selectedCount = 0;

  if (projectTypeCheckbox && projectTypeCheckbox.checked) {
    selectedText += `${selectedText ? ", " : ""}Project`;
    const projectTypeVulnCount = projectTypeCheckbox.getAttribute(
      "data-type-project-count"
    );
    selectedCount += parseInt(projectTypeVulnCount, 10);
  }
  if (osTypeCheckbox && osTypeCheckbox.checked) {
    selectedText += `${selectedText ? ", " : ""}OS`;
    const osTypeVulnCount = osTypeCheckbox.getAttribute("data-type-os-count");
    selectedCount += parseInt(osTypeVulnCount, 10);
  }
  if (uncalledTypeCheckbox && uncalledTypeCheckbox.checked) {
    selectedText += `${selectedText ? ", " : ""}Unimportant`;
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
    layerSelected.textContent = `All layers (${allLayerCheckedBox.getAttribute("data-layer-all-count")})`;
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
    if (allLayerCheckedBox) {
      allLayerCheckedBox.checked = true;
    }
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
  if (vulnSearchInput.value !== "") {
    vulnSearchInput.value = "";
    showAllVulns();
  }
}

function resetTypeCheckbox() {
  const allTypeCheckbox = document.getElementById("all-type-checkbox");
  const osTypeCheckbox = document.getElementById("os-type-checkbox");
  const projectTypeCheckbox = document.getElementById("project-type-checkbox");
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

document.addEventListener("DOMContentLoaded", () => {
  resetFilterText();
  showAndHideParentSections();

  // Implement filter for vulnerability types
  const typeFilterOptions = document.getElementById(
    "type-filter-option-container"
  );

  typeFilterOptions.addEventListener("change", event => {
    resetSearchText();
    const changedElement = event.target;
    const allTypesCheckbox = document.getElementById("all-type-checkbox");
    const projectCheckbox = document.getElementById("project-type-checkbox"); // Project vulnerabilities
    const osCheckbox = document.getElementById("os-type-checkbox"); // OS vulnerabilities
    const uncalledCheckbox = document.getElementById("uncalled-type-checkbox"); // OS vulnerabilities
    selectedTypeFilterValue.clear();

    if (allTypesCheckbox !== null) {
      if (changedElement === allTypesCheckbox) {
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
        const selectedDisplay = document.getElementById(
          "layer-filter-selected"
        );
        const layerCommand = clickedOption.querySelector("p:first-child");
        selectedDisplay.textContent = layerCommand.textContent;

        hideAllFilterOptions();
        applyFilters(selectedTypeFilterValue, selectedLayer);
      }
    });
  }

  // Hide filter options when clicking other parts
  const filterSections = document.querySelectorAll("div.filter");

  document.addEventListener("click", event => {
    if (![...filterSections].some(c => c.contains(event.target))) {
      hideAllFilterOptions();
    }
  });

  // Search bar
  const vulnSearchInput = document.getElementById("vuln-search");
  vulnSearchInput.addEventListener("keyup", () => {
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
      row.classList.toggle("hide-block", !vulnID.includes(searchTerm));
    });
    showAndHideParentSections();
  });

  // Implement tooltips
  document.querySelectorAll(".tooltip").forEach(elem => {
    elem.addEventListener("mouseover", () => {
      const rect = elem.getBoundingClientRect();
      const tooltipElem = elem.querySelector(".tooltiptext");

      tooltipElem.style.left = `${rect.left}px`;
      tooltipElem.style.top = `${rect.top}px`;
    });
  });

  showAllVulns();
});
