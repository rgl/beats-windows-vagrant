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
| template | filebeat-6.6.1 | [_template/filebeat-6.6.1](https://elasticsearch.example.com/_template/filebeat-6.6.1) | contains all the modules definitions |
| pipeline | filebeat-6.6.1-iis-error-default | [_ingest/pipeline/filebeat-6.6.1-iis-error-default](https://elasticsearch.example.com/_ingest/pipeline/filebeat-6.6.1-iis-error-default) | IIS HTTPERR log ingest pipeline |
| pipeline | filebeat-6.6.1-iis-access-default | [_ingest/pipeline/filebeat-6.6.1-iis-access-default](https://elasticsearch.example.com/_ingest/pipeline/filebeat-6.6.1-iis-access-default) | IIS access log ingest pipeline |

Filebeat will tail all the log files for log messages, batch them, then send them in [Elasticsearch bulk requests](https://www.elastic.co/guide/en/elasticsearch/reference/6.5/docs-bulk.html) to a index with the pattern `filebeat-%{[beat.version]}-%{+yyyy.MM.dd}` (e.g. `filebeat-6.6.1-2018.12.30`).

## IIS logs

IIS logs are normally stored at:

* `C:\inetpub\logs\LogFiles\*\*.log`
* `C:\Windows\System32\LogFiles\HTTPERR\*.log`

The IIS logs are buffered for some time (one minute by default) before being flushed/written to disk. You can manually force a flush with the command `netsh http flush logbuffer` (flushes the HTTP.sys log buffer to disk).

The IIS access logs can be customized by selecting which fields will be logged, **BUT, by default, filebeat only supports three configurations**. The three supported configurations are defined as [elasticsearch grok expressions](https://www.elastic.co/guide/en/elasticsearch/reference/6.5/grok-processor.html) inside the `C:\filebeat\module\iis\access\ingest\default.json` file (or the [online version source code](https://github.com/elastic/beats/blob/v6.6.1/filebeat/module/iis/access/ingest/default.json)) and correspond to these:

| #1 | #2 | #3 | IIS field        | filebeat field                 | grok expression                          |
|----|----|----|------------------|--------------------------------|------------------------------------------|
| X  | X  | X  | date time        | iis.access.time                | %{TIMESTAMP_ISO8601:iis.access.time}     |
|    | X  | X  | s-sitename       | iis.access.site_name           | %{NOTSPACE:iis.access.site_name}         |
|    |    | X  | s-computername   | iis.access.server_name         | %{NOTSPACE:iis.access.server_name}       |
| X  |    | X  | s-ip             | iis.access.server_ip           | %{IPORHOST:iis.access.server_ip}         |
| X  | X  | X  | cs-method        | iis.access.method              | %{WORD:iis.access.method}                |
| X  | X  | X  | cs-uri-stem      | iis.access.url                 | %{URIPATH:iis.access.url}                |
| X  | X  | X  | cs-uri-query     | iis.access.query_string        | %{NOTSPACE:iis.access.query_string}      |
| X  | X  | X  | s-port           | iis.access.port                | %{NUMBER:iis.access.port}                |
| X  | X  | X  | cs-username      | iis.access.user_name           | %{NOTSPACE:iis.access.user_name}         |
| X  | X  | X  | c-ip             | iis.access.remote_ip           | %{IPORHOST:iis.access.remote_ip}         |
|    |    | X  | cs-version       | iis.access.http_version        | HTTP/%{NUMBER:iis.access.http_version}   |
| X  | X  | X  | cs(User-Agent)   | iis.access.agent               | %{NOTSPACE:iis.access.agent}             |
|    | X  | X  | cs(Cookie)       | iis.access.cookie              | %{NOTSPACE:iis.access.cookie}            |
| X  | X  | X  | cs(Referer)      | iis.access.referrer            | %{NOTSPACE:iis.access.referrer}          |
|    | X  | X  | cs-host          | iis.access.hostname            | %{NOTSPACE:iis.access.hostname}          |
| X  | X  | X  | sc-status        | iis.access.response_code       | %{NUMBER:iis.access.response_code}       |
| X  | X  | X  | sc-substatus     | iis.access.sub_status          | %{NUMBER:iis.access.sub_status}          |
| X  | X  | X  | sc-win32-status  | iis.access.win32_status        | %{NUMBER:iis.access.win32_status}        |
|    | X  | X  | sc-bytes         | iis.access.body_sent.bytes     | %{NUMBER:iis.access.body_sent.bytes}     |
|    | X  | X  | cs-bytes         | iis.access.body_received.bytes | %{NUMBER:iis.access.body_received.bytes} |
| X  | X  | X  | time-taken       | iis.access.request_time_ms     | %{NUMBER:iis.access.request_time_ms}     |

* **NB** the #1 configuration corresponds to the default IIS logging configuration.
* **NB** the #2 configuration corresponds to the default Azure IIS logging configuration.
* **NB** the #3 configuration corresponds to all the available fields in IIS (as-of IIS 10 that ships with Windows 2019), and this is the one we configure and use in this vagrant environment (see [provision-iis.ps1](provision-iis.ps1)).

### IIS access log example

The following example shows how filebeat sends a IIS access log (**using configuration type #3**) line to Elasticsearch and how its transformed by the pipeline.

Filebeat sends/receives the following bulk request/response:

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
        "_index": "filebeat-6.6.1-2018.12.30",
        "_type": "doc",
        "pipeline": "filebeat-6.6.1-iis-access-default"
    }
}
{
    "@timestamp": "2018-12-30T13:19:43.216Z",
    "fileset": {
        "module": "iis",
        "name": "access"
    },
    "prospector": {
        "type": "log"
    },
    "beat": {
        "version": "6.6.1",
        "name": "beats",
        "hostname": "beats"
    },
    "host": {
        "name": "beats"
    },
    "source": "C:\\inetpub\\logs\\LogFiles\\W3SVC1\\u_ex181230.log",
    "offset": 335,
    "message": "2018-12-30 13:18:52 W3SVC1 beats ::1 GET /four-oh-four - 80 - ::1 HTTP/1.1 Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/71.0.3578.98+Safari/537.36 - - localhost 404 0 2 5044 419 386",
    "input": {
        "type": "log"
    }
}

HTTP/1.1 200 OK
content-type: application/json; charset=UTF-8
content-encoding: gzip
content-length: 123

{
    "took": 36,
    "ingest_took": 12,
    "errors": false,
    "items": [{
        "index": {
            "_index": "filebeat-6.6.1-2018.12.30",
            "_type": "doc",
            "_id": "bYBF_2cBPVbU0mdFMkxx",
            "_version": 1,
            "result": "created",
            "_shards": {
                "total": 2,
                "successful": 1,
                "failed": 0
            },
            "_seq_no": 0,
            "_primary_term": 1,
            "status": 201
        }
    }]
}
```

Which, after being transformed by the filebeat elasticsearch ingest pipeline, will be stored in elasticsearch as this request/response shows:

```json
GET /filebeat-6.6.1-2018.12.30/doc/bYBF_2cBPVbU0mdFMkxx HTTP/1.1
Host: localhost:9200
Connection: close

HTTP/1.1 200 OK
content-type: application/json; charset=UTF-8
content-length: 123

{
    "_index": "filebeat-6.6.1-2018.12.30",
    "_type": "doc",
    "_id": "bYBF_2cBPVbU0mdFMkxx",
    "_version": 1,
    "found": true,
    "_source": {
        "offset": 335,
        "prospector": {
            "type": "log"
        },
        "read_timestamp": "2018-12-30T13:19:43.216Z",
        "source": "C:\\inetpub\\logs\\LogFiles\\W3SVC1\\u_ex181230.log",
        "fileset": {
            "module": "iis",
            "name": "access"
        },
        "input": {
            "type": "log"
        },
        "iis": {
            "access": {
                "server_name": "beats",
                "response_code": "404",
                "cookie": "-",
                "method": "GET",
                "sub_status": "0",
                "user_name": "-",
                "http_version": "1.1",
                "url": "/four-oh-four",
                "site_name": "W3SVC1",
                "referrer": "-",
                "body_received": {
                    "bytes": "419"
                },
                "hostname": "localhost",
                "remote_ip": "::1",
                "port": "80",
                "server_ip": "::1",
                "body_sent": {
                    "bytes": "5044"
                },
                "win32_status": "2",
                "request_time_ms": "386",
                "query_string": "-",
                "user_agent": {
                    "patch": "3578",
                    "original": "Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/71.0.3578.98+Safari/537.36",
                    "major": "71",
                    "minor": "0",
                    "os": "Windows",
                    "name": "Chrome",
                    "os_name": "Windows",
                    "device": "Other"
                }
            }
        },
        "@timestamp": "2018-12-30T13:18:52.000Z",
        "beat": {
            "hostname": "beats",
            "name": "beats",
            "version": "6.6.1"
        },
        "host": {
            "name": "beats"
        }
    }
}
```

The pipeline (the most import part is the [grok processor](https://www.elastic.co/guide/en/elasticsearch/reference/6.5/grok-processor.html) block) is defined as (see the `C:\filebeat\module\iis\access\ingest\default.json` file or the [online version source code](https://github.com/elastic/beats/blob/v6.6.1/filebeat/module/iis/access/ingest/default.json)):

```json
GET _ingest/pipeline/filebeat-6.6.1-iis-access-default

{
    "filebeat-6.6.1-iis-access-default": {
        "description": "Pipeline for parsing IIS access logs. Requires the geoip and user_agent plugins.",
        "processors": [{
                "grok": {
                    "field": "message",
                    "patterns": [
                        "%{TIMESTAMP_ISO8601:iis.access.time} %{IPORHOST:iis.access.server_ip} %{WORD:iis.access.method} %{URIPATH:iis.access.url} %{NOTSPACE:iis.access.query_string} %{NUMBER:iis.access.port} %{NOTSPACE:iis.access.user_name} %{IPORHOST:iis.access.remote_ip} %{NOTSPACE:iis.access.agent} %{NOTSPACE:iis.access.referrer} %{NUMBER:iis.access.response_code} %{NUMBER:iis.access.sub_status} %{NUMBER:iis.access.win32_status} %{NUMBER:iis.access.request_time_ms}",
                        "%{TIMESTAMP_ISO8601:iis.access.time} %{NOTSPACE:iis.access.site_name} %{WORD:iis.access.method} %{URIPATH:iis.access.url} %{NOTSPACE:iis.access.query_string} %{NUMBER:iis.access.port} %{NOTSPACE:iis.access.user_name} %{IPORHOST:iis.access.remote_ip} %{NOTSPACE:iis.access.agent} %{NOTSPACE:iis.access.cookie} %{NOTSPACE:iis.access.referrer} %{NOTSPACE:iis.access.hostname} %{NUMBER:iis.access.response_code} %{NUMBER:iis.access.sub_status} %{NUMBER:iis.access.win32_status} %{NUMBER:iis.access.body_sent.bytes} %{NUMBER:iis.access.body_received.bytes} %{NUMBER:iis.access.request_time_ms}",
                        "%{TIMESTAMP_ISO8601:iis.access.time} %{NOTSPACE:iis.access.site_name} %{NOTSPACE:iis.access.server_name} %{IPORHOST:iis.access.server_ip} %{WORD:iis.access.method} %{URIPATH:iis.access.url} %{NOTSPACE:iis.access.query_string} %{NUMBER:iis.access.port} %{NOTSPACE:iis.access.user_name} %{IPORHOST:iis.access.remote_ip} HTTP/%{NUMBER:iis.access.http_version} %{NOTSPACE:iis.access.agent} %{NOTSPACE:iis.access.cookie} %{NOTSPACE:iis.access.referrer} %{NOTSPACE:iis.access.hostname} %{NUMBER:iis.access.response_code} %{NUMBER:iis.access.sub_status} %{NUMBER:iis.access.win32_status} %{NUMBER:iis.access.body_sent.bytes} %{NUMBER:iis.access.body_received.bytes} %{NUMBER:iis.access.request_time_ms}"
                    ],
                    "ignore_missing": true
                }
            },
            {
                "remove": {
                    "field": "message"
                }
            },
            {
                "rename": {
                    "field": "@timestamp",
                    "target_field": "read_timestamp"
                }
            },
            {
                "date": {
                    "field": "iis.access.time",
                    "target_field": "@timestamp",
                    "formats": [
                        "yyyy-MM-dd HH:mm:ss"
                    ]
                }
            },
            {
                "remove": {
                    "field": "iis.access.time"
                }
            },
            {
                "user_agent": {
                    "field": "iis.access.agent",
                    "target_field": "iis.access.user_agent"
                }
            },
            {
                "rename": {
                    "field": "iis.access.agent",
                    "target_field": "iis.access.user_agent.original"
                }
            },
            {
                "geoip": {
                    "field": "iis.access.remote_ip",
                    "target_field": "iis.access.geoip"
                }
            }
        ],
        "on_failure": [{
            "set": {
                "field": "error.message",
                "value": "{{ _ingest.on_failure_message }}"
            }
        }]
    }
}
```

# Reference

* https://www.elastic.co/guide/en/beats/filebeat/6.5/defining-processors.html
* [Transition Beats to ECS](https://github.com/elastic/beats/issues/8655)
* [Elastic Common Schema (ECS)](https://github.com/elastic/ecs)
