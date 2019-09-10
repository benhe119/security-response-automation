package main

import (
	"fmt"

	"github.com/google/security-response-automation/clients"
	"github.com/google/security-response-automation/cloudfunctions"

	"context"

	"cloud.google.com/go/pubsub"
)

var (
	// folderID specifies which folder RevokeExternalGrantsFolders should remove members from.
	folderIDs = []string{"670032686187"}
	// disallowed contains a list of external domains RevokeExternalGrantsFolders should remove.
	disallowed = []string{"test.com", "gmail.com"}
)

func main() {
	ctx := context.Background()
	m := &pubsub.Message{}
	//

	in := `{
		"insertId": "31y1f6a4",
		"jsonPayload": {
		  "properties": {
			"subnetwork_id": "5369185455554397665",
			"ip": [
			  "54.91.161.78"
			],
			"sourceInstance": "/projects/carise-etdeng-joonix/zones/us-central1-a/instances/instance-1",
			"location": "us-central1-a",
			"subnetwork_name": "default",
			"destinationInstance": "",
			"project_id": "carise-etdeng-joonix"
		  },
		  "detectionCategory": {
			"technique": "cryptomining",
			"ruleName": "bad_ip",
			"indicator": "ip"
		  },
		  "detectionPriority": "HIGH",
		  "affectedResources": [
			{
			  "gcpResourceName": "//cloudresourcemanager.googleapis.com/projects/482856381636"
			}
		  ],
		  "evidence": [
			{
			  "sourceLogId": {
				"insertId": "nbg9n6fr0p8er",
				"timestamp": "2019-09-10T20:57:21.179692365Z"
			  }
			}
		  ],
		  "sourceId": {
			"customerOrganizationNumber": "857541979936",
			"projectNumber": "482856381636"
		  },
		  "eventTime": "2019-09-10T20:57:21.446Z"
		},
		"resource": {
		  "type": "threat_detector",
		  "labels": {
			"project_id": "carise-etdeng-joonix",
			"detector_name": "bad_ip"
		  }
		},
		"timestamp": "2019-09-10T20:57:21.446Z",
		"severity": "CRITICAL",
		"logName": "projects/carise-etdeng-joonix/logs/threatdetection.googleapis.com%2Fdetection",
		"receiveTimestamp": "2019-09-10T20:57:22.668704769Z"
	  }`

	// in := `{
	// 	"insertId": "31y1f6a4",
	// 	"jsonPayload": {
	// 	  "affectedResources": [
	// 		{
	// 		  "gcpResourceName": "//cloudresourcemanager.googleapis.com/projects/997507777601"
	// 		}
	// 	  ],
	// 	  "detectionCategory": {
	// 		"indicator": "audit_log",
	// 		"ruleName": "iam_anomalous_grant",
	// 		"subRuleName": "external_member_added_to_policy",
	// 		"technique": "persistence"
	// 	  },
	// 	  "detectionPriority": "HIGH",
	// 	  "eventTime": "2019-09-09T18:25:49.236Z",
	// 	  "evidence": [
	// 		{
	// 		  "sourceLogId": {
	// 			"insertId": "-kt3q87c71s",
	// 			"timestamp": "2019-09-09T18:25:47.409Z"
	// 		  }
	// 		}
	// 	  ],
	// 	  "properties": {
	// 		"bindingDeltas": [
	// 		  {
	// 			"action": "ADD",
	// 			"member": "user:ccexperts@gmail.com",
	// 			"role": "roles/editor"
	// 		  }
	// 		],
	// 		"externalMembers": [
	// 		  "user:ccexperts@gmail.com"
	// 		],
	// 		"principalEmail": "tom3fitzgerald@gmail.com",
	// 		"project_id": "aerial-jigsaw-235219"
	// 	  },
	// 	  "sourceId": {
	// 		"customerOrganizationNumber": "154584661726",
	// 		"projectNumber": "997507777601"
	// 	  }
	// 	},
	// 	"logName": "projects/aerial-jigsaw-235219/logs/threatdetection.googleapis.com%2Fdetection",
	// 	"receiveTimestamp": "2019-09-09T18:25:50.087113103Z",
	// 	"resource": {
	// 	  "labels": {
	// 		"detector_name": "iam_anomalous_grant",
	// 		"project_id": "aerial-jigsaw-235219"
	// 	  },
	// 	  "type": "threat_detector"
	// 	},
	// 	"severity": "CRITICAL",
	// 	"timestamp": "2019-09-09T18:25:49.236Z"
	//   }`

	m.Data = []byte(in)
	c := clients.New()

	// fmt.Println("init")
	// fmt.Printf("\n%+q", in)
	if err := c.Initialize(); err != nil {
		fmt.Printf("client initialize failed: %q", err)
		return
	}
	fmt.Println("init cc")
	// ids := []string{"111185550749"}
	// disallowed := []string{"gmail.com"}
	// if err := cloudfunctions.RevokeExternalGrantsFolders(ctx, *m, c, ids, disallowed); err != nil {
	// 	fmt.Printf("fail %s", err)
	// 	return
	// }
	if err := cloudfunctions.CreateSnapshot(ctx, *m, c); err != nil {
		fmt.Printf("fail %s", err)
		return
	}
	fmt.Println("done")
}
