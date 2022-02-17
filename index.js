var rule = "";
var parameters = [];
var contentregex = [0,0];
var content = [];
var regex = [];

document.addEventListener('keyup', updateRule)
document.addEventListener('click', updateRule)

function updateRule(){
    rule = "alert ";
    // Protocol
    var protocol = document.getElementById('protocol');
    rule += protocol.options[protocol.selectedIndex].text+" ";
    // Src IP & Port
    rule += document.getElementById('srcip').value+" "+document.getElementById('srcport').value+" ";
    // Direction
    var direction = document.getElementById('direction');
    rule += direction.options[direction.selectedIndex].text+" ";
    // Dst IP & Port
    rule += document.getElementById('dstip').value+" "+document.getElementById('dstport').value+" ";
    // Message
    rule += "(msg:\""+document.getElementById('msg').value+"\"; ";
    // Content
    content.forEach((item)=>{
        rule+="content: \""+document.getElementById('content'+item).value+"\"; ";
    });
    // Nocase
    (parameters.indexOf('nocase')!==-1)?rule+="nocase; ":null;
    // HTTP Method
    (parameters.indexOf('http_method')!==-1)?rule+="http_method; ":null;
    // Regex
    regex.forEach((item)=>{
        rule+="pcre: \""+document.getElementById('regex'+item).value+"\"; ";
    });
    // Threshold
    if (parameters.indexOf('threshold')!==-1) {
        rule+="threshold: ";
        var param;
        param = document.getElementById('thresholdtype');
        rule += "type "+param.options[param.selectedIndex].value+", ";
        param = document.getElementById('trackby');
        rule += "track "+param.options[param.selectedIndex].value+", ";
        rule += "count "+document.getElementById('count').value+", ";
        rule += "seconds "+document.getElementById('seconds').value+"; ";
    }
    // Classtype, SID & Revision
    rule += "classtype: "+document.getElementById('classtype').value+"; sid: "+document.getElementById('sid').value+"; rev: "+document.getElementById('rev').value+";)";
    document.getElementById('generatedsnort').value = rule;
}

function toggleParam(name,state){
    name = name.substr(6,name.length);
    if (state) {
        document.getElementById(name).style.display="block";
        parameters.push(name);
    } else {
        document.getElementById(name).style.display="none";
        parameters.splice(parameters.indexOf(name), 1)
    }
    updateRule()
}

function addTemplate(type){
    var template = document.getElementById(type+'template');
    var clone = template.cloneNode(true);
    clone.id="";
    if (type==="content"){
        contentregex[0]++;
        content.push(contentregex[0]);
        clone.querySelector("input").id=type+contentregex[0];
    } else {
        contentregex[1]++;
        regex.push(contentregex[1]);
        clone.querySelector("input").id=type+contentregex[1];
    }
    document.getElementById(type+"area").appendChild(clone);
}

function removeElement(type, id){
    document.getElementById(id).parentNode.outerHTML="";
    id = parseInt(id.substr(type.length,10));
    if (type==="content"){
        content.splice(content.indexOf(id), 1);
    } else {
        regex.splice(regex.indexOf(id), 1);
    }
}