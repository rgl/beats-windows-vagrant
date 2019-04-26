this is a [Beats](https://www.elastic.co/products/beats) playground

# Usage

[Build and install the Windows 2019 base image](https://github.com/rgl/windows-2016-vagrant).

Launch the `beats` machine:

```bash
vagrant up beats --provider=virtualbox # or --provider=libvirt
```

Logon at the Windows console.

Elasticsearch is available at:

  [https://elasticsearch.example.com](https://elasticsearch.example.com)

Kibana is available at:

  [https://kibana.example.com](https://kibana.example.com)

# Filebeat

Filebeat creates the following Elasticsearch artifacts:

| type     | name           | url                                                                                        | notes                                        |
|----------|----------------|--------------------------------------------------------------------------------------------|----------------------------------------------|
| template | filebeat-7.0.0 | [_template/filebeat-7.0.0](https://elasticsearch.example.com/_template/filebeat-7.0.0) | contains all the modules definitions |
| pipeline | filebeat-7.0.0-iis-error-default | [_ingest/pipeline/filebeat-7.0.0-iis-error-default](https://elasticsearch.example.com/_ingest/pipeline/filebeat-7.0.0-iis-error-default) | IIS HTTPERR log ingest pipeline |
| pipeline | filebeat-7.0.0-iis-access-default | [_ingest/pipeline/filebeat-7.0.0-iis-access-default](https://elasticsearch.example.com/_ingest/pipeline/filebeat-7.0.0-iis-access-default) | IIS access log ingest pipeline |

Filebeat will tail all the log files for log messages, batch them, then send them in [Elasticsearch bulk requests](https://www.elastic.co/guide/en/elasticsearch/reference/7.0/docs-bulk.html) to a index with the pattern `filebeat-%{[beat.version]}-%{+yyyy.MM.dd}` (e.g. `filebeat-7.0.0-2018.12.30`).

## IIS logs

IIS logs are normally stored at:

* `C:\inetpub\logs\LogFiles\*\*.log`
* `C:\Windows\System32\LogFiles\HTTPERR\*.log`

The IIS logs are buffered for some time (one minute by default) before being flushed/written to disk. You can manually force a flush with the command `netsh http flush logbuffer` (flushes the HTTP.sys log buffer to disk).

The IIS access logs can be customized by selecting which fields will be logged, **BUT, by default, filebeat only supports five configurations**. The five supported configurations are defined as [elasticsearch grok expressions](https://www.elastic.co/guide/en/elasticsearch/reference/7.0/grok-processor.html) inside the `C:\filebeat\module\iis\access\ingest\default.json` file (or the [online version source code](https://github.com/elastic/beats/blob/v7.0.0/filebeat/module/iis/access/ingest/default.json)).

The main ones are:

| #1 | #2 | #3 | IIS field       | filebeat field            | grok expression                          |
|----|----|----|-----------------|---------------------------|------------------------------------------|
| X  | X  | X  | date time       | @timestamp                | %{TIMESTAMP_ISO8601:iis.access.time}     |
|    | X  | X  | s-sitename      | iis.access.site_name      | %{NOTSPACE:iis.access.site_name}         |
|    |    | X  | s-computername  | iis.access.server_name    | %{NOTSPACE:iis.access.server_name}       |
| X  |    | X  | s-ip            | destination.address       | %{IPORHOST:destination.address}          |
| X  | X  | X  | cs-method       | http.request.method       | %{WORD:http.request.method}              |
| X  | X  | X  | cs-uri-stem     | url.path                  | %{URIPATH:url.path}                      |
| X  | X  | X  | cs-uri-query    | url.query                 | %{NOTSPACE:url.query}                    |
| X  | X  | X  | s-port          | destination.port          | %{NUMBER:destination.port:long}          |
| X  | X  | X  | cs-username     | user.name                 | %{NOTSPACE:user.name}                    |
| X  | X  | X  | c-ip            | source.address            | %{IPORHOST:source.address}               |
|    |    | X  | cs-version      | http.version              | HTTP/%{NUMBER:http.version}              |
| X  | X  | X  | cs(User-Agent)  | user_agent.original       | %{NOTSPACE:user_agent.original}          |
|    | X  | X  | cs(Cookie)      | iis.access.cookie         | %{NOTSPACE:iis.access.cookie}            |
| X  | X  | X  | cs(Referer)     | http.request.referrer     | %{NOTSPACE:http.request.referrer}        |
|    | X  | X  | cs-host         | destination.domain        | %{NOTSPACE:destination.domain}           |
| X  | X  | X  | sc-status       | http.response.status_code | %{NUMBER:http.response.status_code:long} |
| X  | X  | X  | sc-substatus    | iis.access.sub_status     | %{NUMBER:iis.access.sub_status:long}     |
| X  | X  | X  | sc-win32-status | iis.access.win32_status   | %{NUMBER:iis.access.win32_status:long}   |
|    | X  | X  | sc-bytes        | http.response.body.bytes  | %{NUMBER:http.response.body.bytes:long}  |
|    | X  | X  | cs-bytes        | http.request.body.bytes   | %{NUMBER:http.request.body.bytes:long}   |
| X  | X  | X  | time-taken      | event.duration            | %{NUMBER:temp.duration:long}             |

* **NB** the #1 configuration corresponds to the default IIS logging configuration.
* **NB** the #2 configuration corresponds to the default Azure IIS logging configuration.
* **NB** the #3 configuration corresponds to all the available fields in IIS (as-of IIS 10 that ships with Windows 2019), and this is the one we configure and use in this vagrant environment (see [provision-iis.ps1](provision-iis.ps1)).

### IIS access log example

The following example shows how filebeat sends a IIS access log (**using configuration type #3**) line to Elasticsearch and how its transformed by the pipeline.

Filebeat sends/receives the following bulk request/response:

**NB** these were captured with fiddler by setting `proxy_url` in `filebeat.yml` and accessing `http://localhost/four-oh-four`.

```json
POST /_bulk HTTP/1.1
Host: elasticsearch.example.com:443
User-Agent: Go-http-client/1.1
Content-Length: 123
Accept: application/json
Accept-Encoding: gzip
Content-Type: application/json; charset=UTF-8

{
    "index": {
        "_index": "filebeat-7.0.0-2019.04.26",
        "pipeline": "filebeat-7.0.0-iis-access-default"
    }
}
{
    "@timestamp": "2019-04-26T09:50:43.361Z",
    "message": "2019-04-26 09:50:34 W3SVC1 beats 127.0.0.1 GET /four-oh-four - 80 - 127.0.0.1 HTTP/1.1 Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/74.0.3729.108+Safari/537.36 - - localhost 404 0 2 5044 427 1970",
    "service": {
        "type": "iis"
    },
    "event": {
        "module": "iis",
        "dataset": "iis.access"
    },
    "host": {
        "name": "beats"
    },
    "agent": {
        "type": "filebeat",
        "ephemeral_id": "242e7b2e-be7f-434b-9ed0-200b225306cf",
        "hostname": "beats",
        "id": "5cf266e8-b541-49b6-8ee5-f18d6c7f55c2",
        "version": "7.0.0"
    },
    "log": {
        "offset": 335,
        "file": {
            "path": "C:\\inetpub\\logs\\LogFiles\\W3SVC1\\u_ex190426.log"
        }
    },
    "input": {
        "type": "log"
    },
    "fileset": {
        "name": "access"
    },
    "ecs": {
        "version": "1.0.0"
    }
}

HTTP/1.1 200 OK
content-type: application/json; charset=UTF-8
content-encoding: gzip
content-length: 123

{
    "took": 14,
    "ingest_took": 5,
    "errors": false,
    "items": [{
        "index": {
            "_index": "filebeat-7.0.0-2019.04.26",
            "_type": "_doc",
            "_id": "ZpMNWWoBQLxjzhVU5ryQ",
            "_version": 1,
            "result": "created",
            "_shards": {
                "total": 1,
                "successful": 1,
                "failed": 0
            },
            "_seq_no": 93,
            "_primary_term": 1,
            "status": 201
        }
    }]
}
```

Which, after being transformed by the filebeat elasticsearch ingest pipeline, will be stored in elasticsearch as this request/response shows:

```json
GET /filebeat-7.0.0-2019.04.26/_doc/ZpMNWWoBQLxjzhVU5ryQ HTTP/1.1
Host: localhost:9200
Connection: close

HTTP/1.1 200 OK
content-type: application/json; charset=UTF-8
content-length: 123

{
    "_index": "filebeat-7.0.0-2019.04.26",
    "_type": "_doc",
    "_id": "ZpMNWWoBQLxjzhVU5ryQ",
    "_version": 1,
    "_seq_no": 93,
    "_primary_term": 1,
    "found": true,
    "_source": {
        "agent": {
            "hostname": "beats",
            "id": "5cf266e8-b541-49b6-8ee5-f18d6c7f55c2",
            "type": "filebeat",
            "ephemeral_id": "242e7b2e-be7f-434b-9ed0-200b225306cf",
            "version": "7.0.0"
        },
        "temp": {},
        "log": {
            "file": {
                "path": "C:\\inetpub\\logs\\LogFiles\\W3SVC1\\u_ex190426.log"
            },
            "offset": 335
        },
        "destination": {
            "address": "127.0.0.1",
            "port": 80,
            "domain": "localhost",
            "ip": "127.0.0.1"
        },
        "source": {
            "address": "127.0.0.1",
            "ip": "127.0.0.1"
        },
        "fileset": {
            "name": "access"
        },
        "url": {
            "path": "/four-oh-four",
            "query": "-"
        },
        "input": {
            "type": "log"
        },
        "iis": {
            "access": {
                "site_name": "W3SVC1",
                "server_name": "beats",
                "cookie": "-",
                "sub_status": 0,
                "win32_status": 2
            }
        },
        "@timestamp": "2019-04-26T09:50:34.000Z",
        "ecs": {
            "version": "1.0.0"
        },
        "service": {
            "type": "iis"
        },
        "host": {
            "name": "beats"
        },
        "http": {
            "request": {
                "referrer": "-",
                "method": "GET",
                "body": {
                    "bytes": 427
                }
            },
            "response": {
                "status_code": 404,
                "body": {
                    "bytes": 5044
                }
            },
            "version": "1.1"
        },
        "event": {
            "duration": 1970000000,
            "created": "2019-04-26T09:50:43.361Z",
            "module": "iis",
            "dataset": "iis.access"
        },
        "user": {
            "name": "-"
        },
        "user_agent": {
            "original": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.108 Safari/537.36",
            "os": {
                "name": "Windows 10"
            },
            "name": "Chrome",
            "device": {
                "name": "Other"
            },
            "version": "74.0.3729"
        }
    }
}
```

The pipeline (the most import part is the [grok processor](https://www.elastic.co/guide/en/elasticsearch/reference/7.0/grok-processor.html) block) is defined as (see the `C:\filebeat\module\iis\access\ingest\default.json` file or the [online version source code](https://github.com/elastic/beats/blob/v7.0.0/filebeat/module/iis/access/ingest/default.json)):

```json
GET _ingest/pipeline/filebeat-7.0.0-iis-access-default

{
    "filebeat-7.0.0-iis-access-default": {
        "processors": [{
            "grok": {
                "field": "message",
                "patterns": [
                    "%{TIMESTAMP_ISO8601:iis.access.time} %{IPORHOST:destination.address} %{WORD:http.request.method} %{URIPATHWITHBRACKET:url.path} %{NOTSPACE:url.query} %{NUMBER:destination.port:long} %{NOTSPACE:user.name} %{IPORHOST:source.address} %{NOTSPACE:user_agent.original} %{NOTSPACE:http.request.referrer} %{NUMBER:http.response.status_code:long} %{NUMBER:iis.access.sub_status:long} %{NUMBER:iis.access.win32_status:long} %{NUMBER:temp.duration:long}",
                    "%{TIMESTAMP_ISO8601:iis.access.time} %{NOTSPACE:iis.access.site_name} %{WORD:http.request.method} %{URIPATH:url.path} %{NOTSPACE:url.query} %{NUMBER:destination.port:long} %{NOTSPACE:user.name} %{IPORHOST:source.address} %{NOTSPACE:user_agent.original} %{NOTSPACE:iis.access.cookie} %{NOTSPACE:http.request.referrer} %{NOTSPACE:destination.domain} %{NUMBER:http.response.status_code:long} %{NUMBER:iis.access.sub_status:long} %{NUMBER:iis.access.win32_status:long} %{NUMBER:http.response.body.bytes:long} %{NUMBER:http.request.body.bytes:long} %{NUMBER:temp.duration:long}",
                    "%{TIMESTAMP_ISO8601:iis.access.time} %{NOTSPACE:iis.access.site_name} %{NOTSPACE:iis.access.server_name} %{IPORHOST:destination.address} %{WORD:http.request.method} %{URIPATH:url.path} %{NOTSPACE:url.query} %{NUMBER:destination.port:long} %{NOTSPACE:user.name} %{IPORHOST:source.address} HTTP/%{NUMBER:http.version} %{NOTSPACE:user_agent.original} %{NOTSPACE:iis.access.cookie} %{NOTSPACE:http.request.referrer} %{NOTSPACE:destination.domain} %{NUMBER:http.response.status_code:long} %{NUMBER:iis.access.sub_status:long} %{NUMBER:iis.access.win32_status:long} %{NUMBER:http.response.body.bytes:long} %{NUMBER:http.request.body.bytes:long} %{NUMBER:temp.duration:long}",
                    "%{TIMESTAMP_ISO8601:iis.access.time} \\[%{IPORHOST:destination.address}\\]\\(http://%{IPORHOST:destination.address}\\) %{WORD:http.request.method} %{URIPATH:url.path} %{NOTSPACE:url.query} %{NUMBER:destination.port:long} %{NOTSPACE:user.name} \\[%{IPORHOST:source.address}\\]\\(http://%{IPORHOST:source.address}\\) %{NOTSPACE:user_agent.original} %{NUMBER:http.response.status_code:long} %{NUMBER:iis.access.sub_status:long} %{NUMBER:iis.access.win32_status:long} %{NUMBER:temp.duration:long}",
                    "%{TIMESTAMP_ISO8601:iis.access.time} %{IPORHOST:destination.address} %{WORD:http.request.method} %{URIPATH:url.path} %{NOTSPACE:url.query} %{NUMBER:destination.port:long} %{NOTSPACE:user.name} %{IPORHOST:source.address} %{NOTSPACE:user_agent.original} %{NUMBER:http.response.status_code:long} %{NUMBER:iis.access.sub_status:long} %{NUMBER:iis.access.win32_status:long} %{NUMBER:temp.duration:long}"
                ],
                "pattern_definitions": {
                    "URIPATHWITHBRACKET": "(?:/[A-Za-z0-9$.+!*'(){},~:;=@#%&_\\-\\[\\]]*)+"
                },
                "ignore_missing": true
            }
        }, {
            "remove": {
                "field": "message"
            }
        }, {
            "rename": {
                "field": "@timestamp",
                "target_field": "event.created"
            }
        }, {
            "date": {
                "field": "iis.access.time",
                "target_field": "@timestamp",
                "formats": ["yyyy-MM-dd HH:mm:ss"]
            }
        }, {
            "remove": {
                "field": "iis.access.time"
            }
        }, {
            "script": {
                "params": {
                    "scale": 1000000.0
                },
                "if": "ctx.temp?.duration != null",
                "lang": "painless",
                "source": "ctx.event.duration = Math.round(ctx.temp.duration * params.scale)"
            }
        }, {
            "remove": {
                "field": "temp.duration",
                "ignore_missing": true
            }
        }, {
            "urldecode": {
                "field": "user_agent.original"
            }
        }, {
            "user_agent": {
                "field": "user_agent.original"
            }
        }, {
            "grok": {
                "field": "destination.address",
                "ignore_failure": true,
                "patterns": ["%{NOZONEIP:destination.ip}"],
                "pattern_definitions": {
                    "NOZONEIP": "[^%]*"
                }
            }
        }, {
            "grok": {
                "field": "source.address",
                "ignore_failure": true,
                "patterns": ["%{NOZONEIP:source.ip}"],
                "pattern_definitions": {
                    "NOZONEIP": "[^%]*"
                }
            }
        }, {
            "geoip": {
                "field": "source.ip",
                "target_field": "source.geo",
                "ignore_missing": true
            }
        }],
        "on_failure": [{
            "set": {
                "field": "error.message",
                "value": "{{ _ingest.on_failure_message }}"
            }
        }],
        "description": "Pipeline for parsing IIS access logs. Requires the geoip and user_agent plugins."
    }
}
```

# Reference

* https://www.elastic.co/guide/en/beats/filebeat/7.0/defining-processors.html
* [Transition Beats to ECS](https://github.com/elastic/beats/issues/8655)
* [Elastic Common Schema (ECS)](https://github.com/elastic/ecs)
