let event_count=0;

function processWindowsLog() {
    event_count = 0;
    document.getElementById("tbody").innerHTML="";
    var raw_input = document.getElementById("inputbox").value;
    var logList = stripAndSplit(raw_input);
    logList.forEach(processLine);
};

function stripAndSplit(text) {
    var textList = text.split(/\r?\n/);
    textList = textList.filter(function (item) {
        return item != null && item != "";
    });
    return textList;
}

function stripAndSplitComma(text) {
    var textList = text.split(/\r?,/);
    textList = textList.filter(function (item) {
        return item != null && item != "";
    });
    return textList;
}

function processLine(item) {
    event_count+=1;
    var template = document.getElementById("tr_template");
    var clone = template.content.cloneNode(true);
    
    extractedList = item.match(/\%NICWIN-\d-Security_(\d+)_.+,(\w+ \w+ \d+ \d+:\d+:\d+ \d+)/);

    clone.getElementById("event_count").innerHTML = event_count;
    // Event ID
    event_id = extractedList[1]
    clone.getElementById("event_id").innerHTML = event_id;
    // Date & Time
    clone.getElementById("datetime").innerHTML = extractedList[2];

    everythingElse = item.match(/\%NICWIN-\d-Security_\d+_.+,\w+ \w+ \d+ \d+:\d+:\d+ \d+,\d+,(.*)/)[1];
    listOfEverythingElse = stripAndSplitComma(everythingElse);

    if (eventID.hasOwnProperty(event_id)) {
        Object.keys(eventID[event_id]).forEach((property)=>{
            try {
                item = property + ": " + everythingElse.match(eventID[event_id][property])[1];
            } catch {
                item = property + ": (Nothing returned)";
            }
            clone.getElementById("event_details").appendChild(document.createTextNode(item));
            clone.getElementById("event_details").appendChild(document.createElement("br")); 
        })
    } else {
        listOfEverythingElse.forEach((item)=>{
            clone.getElementById("event_details").appendChild(document.createTextNode(item));
            clone.getElementById("event_details").appendChild(document.createElement("br"));   
        });
    }

    document.getElementById("tbody").appendChild(clone);
}

const eventID = {
    "4624": {
        "Audit Status": /(Audit \w+)/,
        "Security ID": /Security ID:(\w\-\d+\-\d+\-\d+)/,
        "Account Name": /Account Name: (\S+) Account/,
        "Account Domain": /Account Domain: (\S+) Logon/,
        "Logon Type": /Logon Type: (\d+)/,
        "Account Name": /Account Name: \S+ .* Account Name: (\S+)/,
        "Workstation Name": /Workstation Name: (\S+)/,
        "Source IP": /Source Network Address: (\d+\.\d+\.\d+\.\d+)/,
        "Source Port": /Source Port: (\d+)/,
    },
    "4625": {
        "Audit Status": /(Audit \w+)/,
        "AD Domain": /Audit \w+,(\S+),Logon/,
        "Security ID": /Security ID:(\w\-\d+\-\d+\-\d+)/,
        "Account Name": /Account Name: (\S+) Account/,
        "Account Domain": /Account Domain: (\S+) Logon/,
        "Logon Type": /Logon Type: (\d+)/,
        "Account Name": /Account Name: \S+ .* Account Name: (\S+)/,
        "Workstation Name": /Workstation Name: (\S+)/,
        "Source IP": /Source Network Address: (\d+\.\d+\.\d+\.\d+)/,
        "Source Port": /Source Port: (\d+)/,
    }
}