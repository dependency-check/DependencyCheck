function convert() {
    resetAlerts();
    var purl = $('#purl').val();
    console.log('Converting ' + purl);
    try {
        var pobj = PackageURL.fromString(purl);
        if (pobj.hasOwnProperty('namespace')) {
            console.log('Converting ' + JSON.stringify(pobj));

            $('#coord').text(
                    '<dependency>\n' +
                    '  <groupId>' + pobj.namespace + '</groupId>\n' +
                    '  <artifactId>' + pobj.name + '</artifactId>\n' +
                    '  <version>' + pobj.version + '</version>\n' +
                    '</dependency>\n'
                    );
            copyToClipboard();
        } else {
            console.log('invalid');
            showAlert('#invalid');
        }
    } catch (err) {
        console.log('invalid purl ' + err);
        showAlert('#invalid');
    }
}

function copyToClipboard() {
    $('#coord').select();
    try {
        var success = document.execCommand('copy');
        if (success) {
            showAlert('#success');
        } else {
            showAlert('#error');
        }
    } catch (err) {
        showAlert('#error');
        console.log('errored' + err);
    }
    document.getSelection().removeAllRanges();
    $('#purl').select();
    /*
     var $temp = $("<textarea>");
     $("body").append($temp);
     $temp.val($(element).text()).select();
     document.execCommand("copy");
     $temp.remove();
     */
}
function showAlert(id) {
    $(id).show().prop('role', 'alert').fadeOut(6000);
}
function resetAlerts() {
    $('#success').removeProp('role');
    $('#error').removeProp('role');
    $('#invalid').removeProp('role');
}
$(function () {
    $('#purl').on('keypress', function (e) {
        if (e.which == 13) {
            convert();
        }
    });
    $('#purl').on('paste', function () {
        setTimeout(function () {
            convert();
        }, 100);
    });
});

