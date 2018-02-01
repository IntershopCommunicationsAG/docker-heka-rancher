# Heka

Heka is a streaming tool to send log output directly to kafka.

This image configures a heka streamer (using confd with Rancher as backend) to send nginx messages and haproxy messages to a given kafka topic.

Heka listens on:
* port 514 for nginx messages
* port 2514 for haproxy messages

Configuration allows to specify:
* kafka servers via `metadata/kafka/addrs`
* kafka topic for nginx via `metadata/kafka/nginxTopic`
* kafka topic for haproxy via `metadata/kafka/haproxyTopic`
See example configuration below.

# Example Rancher configuration

`docker-compose.yml`:

```
version: '2'
services:
  heka:
    image: lixhunter/heka-rancher:latest
    labels:
      io.rancher.container.pull_image: always
```

`rancher-compose.yml`:

```
version: '2'
services:
  heka:
    scale: 1
    start_on_create: true
    metadata:
      kafka:
        addrs: '"kafka01.example.com:9092", "kafka02.example.com:9092"'
        nginxTopic: WebProxy
        haproxyTopic: LoadBalancer
        waitForElection: 5000
```

# License

Copyright 2014-2017 Intershop Communications.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

# Third-party License heka-docker

Github: https://github.com/ianneub/docker-heka
Dockerhub: https://hub.docker.com/r/ianneub/heka

```
The MIT License (MIT)

Copyright (c) 2014 Ian Neubert

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

# Third-party License mozilla-services heka

Github: https://github.com/mozilla-services/heka

```
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
#
# The Initial Developer of the Original Code is the Mozilla Foundation.
# Portions created by the Initial Developer are Copyright (C) 2012
# the Initial Developer. All Rights Reserved.
#
# Contributor(s):
#   Ben Bangert (bbangert@mozilla.com)
#   Mike Trinkala (mtrinkala@mozilla.com)
#   Rob Miller (rmiller@mozilla.com)
#   Victor Ng (vng@mozilla.com)
#   David Birdsong (david@imgix.com)
#   Michael Gibson (michael.gibson79@gmail.com)
```
