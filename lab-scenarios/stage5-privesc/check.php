<?php
$token = file_get_contents("/var/run/secrets/kubernetes.io/serviceaccount/token");
$data = json_encode(["kind"=>"SelfSubjectRulesReview","apiVersion"=>"authorization.k8s.io/v1","spec"=>["namespace"=>"security-lab"]]);
$opts = [
  "http" => [
    "method" => "POST",
    "header" => "Authorization: Bearer $token\r\nContent-Type: application/json\r\n",
    "content" => $data,
    "ignore_errors" => true
  ],
  "ssl" => [
    "cafile" => "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
    "verify_peer" => true,
    "verify_peer_name" => true
  ]
];
$context = stream_context_create($opts);
$result = file_get_contents("https://kubernetes.default.svc/apis/authorization.k8s.io/v1/selfsubjectrulesreviews", false, $context);
echo $result . "\n";
