<!--

// Edgecore DeviceManager
// Copyright 2020-2021 Edgecore Networks, Inc.
//
// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements. See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership. The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License. You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. See the License for the
// specific language governing permissions and limitations
// under the License.

-->


<pre>
<?php
$host_name = $_GET["host_name"];
$status = $_GET["status"];
$address = $_GET["address"];
$command = "sudo /usr/bin/python3 /usr/lib/nagios/plugins/grpc/proto/grpc_client.py --dm-ip 192.168.8.41:31085 --device-ip ${address}:8888 --getthermalsensorinfo";
echo $command;
$output = shell_exec($command);
echo $output;

echo "------------------------------------------------------------------------\n";

//$command2 = "sudo /usr/bin/python3 /usr/lib/nagios/plugins/grpc/proto/grpc_client.py --dm-ip 192.168.8.41:31085 --device-ip ${address}:8888 ----getpsupowerinfo";
//echo $command2;
//$output2 = shell_exec($command2);
//echo $output2;


?>
</pre>

