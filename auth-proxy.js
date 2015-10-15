var express = require('express');
var body_parser = require('body-parser');
var Q = require('q');
var fs = require('fs');
var path = require('path');
var child_process = require('child_process');
var pem = require('pem');
var mongodb = require('mongodb');
var base64_regex = require('base64-regex');
var http_proxy = require('http-proxy');

var MongoClient = mongodb.MongoClient;
var ObjectID = mongodb.ObjectID;

var app = express();
var proxy = http_proxy.createProxyServer();

var db, users, zones;

var cwd = process.cwd();
var certs = path.join(cwd, 'certs');
var output = path.join(cwd, 'tmp');

app.set('view engine', 'jade');
app.set('views', path.join(cwd, 'public'));

app.use(body_parser.json());
app.use(body_parser.urlencoded());

app.use('/auth-proxy/static', express.static(path.join(cwd, 'public')));

app.get('/auth-proxy/static/*.html', function(req, res) {
    var filename = path.basename(req.originalUrl, '.html');
    res.render(filename);
});


MongoClient.connect('mongodb://localhost:27017/auth-proxy', function(err, db) {
    db = db;
    users = db.collection('users');
    zones = db.collection('zones');
});

var registration = true;

app.use('/', function(req, res, next) {
    if(!registration && req.headers['x-ap-authenticated'] !== 'SUCCESS') {
        res.status(404).render('denied');
        return;
    }

    next();
});

function init_user(csr, username) {
    var deferred = Q.defer();

    if(!username.match(/^[A-Za-z0-9_]+$/)) {
        deferred.reject({ err: 'bad_username' });
        return;
    }

    username = username.toLowerCase();

    users.insert({ username: username }, {}, function(err, user) {
        if(err) {
            deferred.reject({ err: err });
        } else {
            deferred.resolve([ csr, username ]);
        }
    });

    return deferred.promise;
}

function write_cert(data) {
    var spkac = data[0];
    var username = data[1];

    var deferred = Q.defer();

    spkac = spkac.replace(/[\n\r]/g, '');
    if(!base64_regex({ exact: true }).test(spkac)) {
        deferred.reject(err);
        return deferred.promise;
    }

    spkac  = 'SPKAC=' + spkac;
    spkac += '\nCN=' + username;

    fs.writeFile(path.join(certs, username + '.csr'), spkac, function(err) {
        if(err) {
            deferred.reject(err);
            return;
        }

        deferred.resolve(username);
    });

    return deferred.promise;
}

function sign_cert(username) {
    var deferred = Q.defer();

    var openssl = child_process.spawn('openssl', [ 'ca', '-config', path.join(certs, 'ca.cnf'),
        '-spkac', path.join(certs, username + '.csr'), '-out', path.join(output, username + '.crt'),
        '-batch', '-days', 3650
    ]);
    
    var buffer = '';
    var error_buffer = '';

    openssl.stdout.on('data', function(data) {
        buffer += data;
    });

    openssl.stderr.on('data', function(data) {
        error_buffer += data;
    });

    openssl.on('close', function(code) {
        fs.unlink(path.join(certs, username + '.csr'), function(err) { });

        if(code !== 0) {
            deferred.reject('Non-zero exit code from openssl: ' + code);
            return;
        }

        deferred.resolve({ stdout: buffer, code: code, username: username });
    });

    return deferred.promise;
}

app.post('/auth-proxy/api/csr', function(req, res) {
    init_user(req.body.csr, req.body.username).then(write_cert).then(sign_cert).then(function(out) {
        res.download(path.join(output, out.username + '.crt'));
        res.type('application/x-x509-user-cert');
    }).catch(function(err) {
        res.status(500).render('error');
    });
});

app.get('/auth-proxy/api/headers', function(req, res) {
    res.jsonp(req.headers);
});

function parse_cert(_certificate) {
    var certificate = '';
    var character;

    _certificate = _certificate.replace(/-----(BEGIN|END) CERTIFICATE-----/g, '');

    certificate += '-----BEGIN CERTIFICATE-----\n';

    for(var i=0, offset=0; (character=_certificate[i]); i++, offset++) {
        if(offset == 64) {
            certificate += '\n';
            offset = 0;
        }

        if(character == '\n') {
            offset = 0;
        }

        certificate += character;
    }

    certificate += '\n-----END CERTIFICATE-----\n';

    return certificate;
}

function get_username(certificate) {
    var deferred = Q.defer();

    pem.readCertificateInfo(certificate, function(err, info) {
        if(err) {
            deferred.reject(err);
        } else {
            deferred.resolve(info.commonName);
        }
    });

    return deferred.promise;
}

function get_user(username) {
    var deferred = Q.defer();

    users.findOne({ username: username }, function(err, user) {
        if(err) {
            deferred.reject(err);
        } else if(!user) {
            if(!username.match(/^[A-Za-z0-9_]+$/)) {
                deferred.reject({ err: 'bad_username' });
                return;
            }

            username = username.toLowerCase();

            users.insert({ username: username }, {}, function(err, user) {
                if(err) {
                    deferred.reject({ err: err });
                } else {
                    deferred.resolve(user);
                }
            });
        } else {
            deferred.resolve(user);
        }
    });

    return deferred.promise;
}

app.use(function(req, res, next) {
    if(req.headers['x-ap-authenticated'] !== 'SUCCESS') {
        res.render('index');
        return;
    }

    req.headers['x-ap-certificate'] = parse_cert(req.headers['x-ap-certificate']);
    req.auth_host = req.headers['x-ap-host'].replace(/\./g, '-');

    get_username(req.headers['x-ap-certificate']).then(get_user).then(function(user) {
        req.user = user;
        next();
    }).catch(function(err) {
        console.log(err);
        res.status(500).render('error');
    });
});

function privs(user, domain, privilege) {
    domain = domain.toLowerCase();
    privilege = privilege.toLowerCase();

    if(user.groups && user.groups[domain] && user.groups[domain][privilege]) {
        return true;
    }
}

function get_policy(host) {
    var deferred = Q.defer();

    zones.findOne({ hostname: host }, function(err, zone) {
        var policy;

        if(err) {
            deferred.reject(err);
            return;
        }

        if(!zone || !zone.policy) {
            policy = 'allow';
        } else {
            policy = zone.policy;
        }

        deferred.resolve(policy);
    });

    return deferred.promise;
}

function can_read(user, host) {
    var deferred = Q.defer();

    var global_read = privs(user, 'auth-proxy', 'viewer');
    var global_banned = privs(user, 'auth-proxy', 'banned');
    var global_admin = privs(user, 'auth-proxy', 'admin');

    var site_read = privs(user, host, 'viewer');
    var site_banned = privs(user, host, 'banned');
    var site_admin = privs(user, host, 'admin')

    if(site_banned && !site_admin && !global_admin) {
        deferred.reject();
        return deferred.promise;
    }

    if(global_banned && !site_admin && !global_admin) {
        deferred.reject();
        return deferred.promise;
    }

    if(site_admin || global_admin || global_read || site_read) {
        deferred.resolve();
        return deferred.promise;
    }

    get_policy(host).then(function(policy) {
        if(policy === 'allow') {
            deferred.resolve();
        } else {
            deferred.reject();
        }
    }).catch(function(err) {
        deferred.reject();
    });

    return deferred.promise;
}

function forward(req, res) {
    var target = req.headers['x-ap-forward-to'];

    delete req.headers['x-ap-username'];
    delete req.headers['x-ap-authenticated'];
    delete req.headers['x-ap-certificate'];
    delete req.headers['x-ap-forward-to'];
    delete req.headers['x-ap-host'];

    req.headers['x-ap-username'] = req.user.username;

    req.url = req.baseUrl + req.url;

    can_read(req.user, req.auth_host).then(function() {
        proxy.web(req, res, { target: target }, function(e) {
            if(e) {
                console.trace(e);
            }
        });
    }).catch(function(err) {
        console.error(err);
        res.status(404).render('denied');
    });
}

app.use('/auth-proxy/admin', function(req, res, next) {
    req.auth_host = req.headers['x-ap-host'].replace(/\./g, '-');

    req.site_admin = privs(req.user, req.auth_host, 'admin');
    req.net_admin = privs(req.user, 'auth-proxy', 'admin');

    console.log(req.user, req.auth_host);

    if(!req.site_admin && !req.net_admin) {
        forward(req, res);
    } else {
        next();
    }
});

app.get('/auth-proxy/admin/api/policy', function(req, res) {
    get_policy(req.auth_host).then(function(policy) {
        res.jsonp({ policy: policy });
    }).catch(function(err) {
        res.status(500).jsonp({ err: err });
    });
});

app.post('/auth-proxy/admin/api/policy', function(req, res) {
    var policy = req.body.policy;

    if([ 'deny', 'allow' ].indexOf(policy) === -1) {
        res.status(500).jsonp({ err: 'invalid policy, must be deny or allow.' });
        return;
    }

    zones.findOne({ hostname: req.auth_host }, function(err, zone) {
        if(err) {
            res.status(500).jsonp({ err: err });
            return;
        }

        if(!zone) {
            zones.insert({
                hostname: req.auth_host,
                policy: policy
            }, function(err, zone) {
                if(err) {
                    res.status(500).jsonp({ err: err });
                    return;
                }

                res.jsonp(zone);
            });

            return;
        }

        if(zone.policy === policy) {
            res.jsonp(zone);
            return;
        }

        zone.policy = policy;

        zones.update({ hostname: req.auth_host }, zone, function(err, zone) {
            if(err) {
                res.status(500).jsonp({ err: err });
                return;
            }

            res.jsonp(zone);
        });
    });
});

app.get('/auth-proxy/admin/api/users', function(req, res) {
    var query = {
        username: {
            '$exists': true,
            '$ne': null
        }
    };

/*
    if(!req.net_admin) {
        query['groups.' + req.auth_host] = {
            '$exists': true
        };
    }
*/

    users.find(query).toArray(function(err, _users) {
        res.jsonp({ users: _users });
    });
});

app.post('/auth-proxy/admin/api/users/:username/group', function(req, res) {
    if(!req.body.group.match(/[A-Za-z]+/)) {
        res.status(500).jsonp({ err: 'Non-alphabetic character in group.' });
        return;
    }

    var group = req.body.group.toLowerCase();

    if(!req.param_user.groups) {
        req.param_user.groups = { };
    }

    if(!req.param_user.groups[req.auth_host]) {
        req.param_user.groups[req.auth_host] = {};
    }

    req.param_user.groups[req.auth_host][group] = true;

    users.update({ username: req.param_user.username }, req.param_user, function(err, user) {
        if(err) {
            res.status(500).jsonp({ err: err });
            return;
        }

        res.jsonp(user);
    });
});

app.delete('/auth-proxy/admin/api/users/:username/group/:group', function(req, res) {
    delete req.param_user.groups[req.auth_host][req.param_group];

    users.update({ username: req.param_user.username }, req.param_user, function(err, user) {
        if(err) {
            res.status(500).jsonp({ err: err });
            return;
        }

        res.jsonp(user);
    });
});

app.param('username', function(req, res, next, username) {
    users.findOne({ username: username }, function(err, user) {
        if(err) {
            res.status(404).jsonp({ err: 'No such user.' });
            return;
        }

        req.param_user = user;
        next();
    });
});

app.param('group', function(req, res, next, group) {
    if(privs(req.param_user, req.auth_host, group)) {
        req.param_group = group;
        next();
    } else {
        res.status(404).jsonp({ err: 'User not in group.' });
    }
});

app.use('/auth-proxy/admin', express.static(path.join(cwd, 'admin')));

app.get('/auth-proxy/admin', function(req, res) {
    res.render(path.join(path.join(cwd, 'admin'), 'index.jade'));
});

app.all('*', function(req, res) {
    forward(req, res);
});

app.listen(8183, 'localhost');
