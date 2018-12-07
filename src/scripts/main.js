var dateTime = new Date();
var formSignIn = document.querySelector('.form-signin');
var inputExp = formSignIn.querySelector('#exp');
var dateTimePicker = $('#datetimepicker1');
var authorizerResponse = document.querySelector('.authorizer-response');

var syncDateTime = function (event) {
    inputExp.value = event.date.valueOf() / 1000 | 0 || ''
};

formSignIn.addEventListener('submit', function (e) {
    e.preventDefault();

    const formData = new FormData(formSignIn);

    fetch('/request_access', {
        credentials: 'include',
        method: 'post',
        body: formData
    })
            .then(function (response) {
                if (response.status !== 200)
                    throw new Error(response.statusText);

                return response.text()
            })
            .then(function (body) {
                if (body.indexOf('http') === 0) {
                    body = '<a href="' + body + '">' + body + '</a>';
                    body = '<p>The link below grants the requested access. Either visit it yourself, or\n' +
                            '   send it to the intended party.</p>' + body;
                }

                authorizerResponse.innerHTML = body;
                authorizerResponse.classList.add('show');
            })
            .catch(function (ex) {
                authorizerResponse.innerHTML = ex;
                authorizerResponse.classList.add('show');
            });
});

dateTimePicker.datetimepicker({
    format: 'DD/MM/YYYY HH:MM',
    minDate: dateTime,
    defaultDate: dateTime.setDate(dateTime.getDate() + 1)
});

dateTimePicker.on('change.datetimepicker', syncDateTime);

var expiresInOneDay = dateTime.getTime() / 1000 | 0;
document.getElementById('exp').value = expiresInOneDay;

var xhr = new XMLHttpRequest();
xhr.onreadystatechange = function () {
    if (xhr.readyState === 4 && xhr.status === 200) {
        var div = document.getElementById('domains');
        var domains = JSON.parse(xhr.responseText);

        for (var domain in domains) {
            var container = document.createElement('div');
            container.className = 'form-check';

            var label = document.createElement('label');
            label.className = "form-check-label";
            label.setAttribute("for", domains[domain]);

            var el = document.createElement('input');
            el.setAttribute("id", domains[domain]);
            el.name = domains[domain];
            el.className = "form-check-input";
            el.type = "checkbox";
            //el.checked = "checked";
            label.appendChild(document.createTextNode(domains[domain]));
            container.appendChild(el);
            container.appendChild(label);
            div.appendChild(container);
        }
    }
};
xhr.open("GET", 'domain_list', true);
xhr.send(null);
