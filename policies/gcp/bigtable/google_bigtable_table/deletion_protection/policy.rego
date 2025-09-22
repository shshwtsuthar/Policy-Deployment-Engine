package terraform.gcp.security.bigtable.google_bigtable_table.deletion_protection

import data.terraform.gcp.helpers
import data.terraform.gcp.security.bigtable.google_bigtable_table.vars

conditions := [
    [
    {"situation_description" : "The Google Cloud Bigtable table is configured without deletion protection enabled. Tables in Bigtable can contain vast amounts of critical business data, and without deletion protection, they are vulnerable to accidental deletion through API calls, console operations, or automated scripts. This poses a severe risk of irreversible data loss that could impact business operations, compliance requirements, and data recovery capabilities.",
    "remedies":[  "Enable deletion_protection by setting 'deletion_protection = true' for the Bigtable table resource.",
      "Implement proper backup strategies before modifying deletion protection settings.",
      "Review IAM permissions to ensure only authorized personnel can modify table deletion settings.",
      "Establish change management procedures for table lifecycle operations."]},
    {
        "condition": "Google Cloud Bigtable table should have 'deletion_protection' enabled to prevent accidental data loss.",
        "attribute_path" : ["deletion_protection"], 
        "values" : [true], 
        "policy_type" : "whitelist" 
    }
    ]
]

message := helpers.get_multi_summary(conditions, vars.variables).message
details := helpers.get_multi_summary(conditions, vars.variables).details


