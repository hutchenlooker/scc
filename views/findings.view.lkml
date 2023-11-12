# Un-hide and use this explore, or copy the joins into another explore, to get all the fully nested relationships from this view
explore: findings {
  # hidden: yes
    join: findings__finding__files {
      view_label: "Findings: Finding Files"
      sql: LEFT JOIN UNNEST(${findings.finding__files}) as findings__finding__files ;;
      relationship: one_to_many
    }
    join: findings__finding__processes {
      view_label: "Findings: Finding Processes"
      sql: LEFT JOIN UNNEST(${findings.finding__processes}) as findings__finding__processes ;;
      relationship: one_to_many
    }
    join: findings__finding__indicator__uris {
      view_label: "Findings: Finding Indicator Uris"
      sql: LEFT JOIN UNNEST(${findings.finding__indicator__uris}) as findings__finding__indicator__uris ;;
      relationship: one_to_many
    }
    join: findings__finding__processes__args {
      view_label: "Findings: Finding Processes Args"
      sql: LEFT JOIN UNNEST(${findings__finding__processes.args}) as findings__finding__processes__args ;;
      relationship: one_to_many
    }
    join: findings__finding__containers {
      view_label: "Findings: Finding Containers"
      sql: LEFT JOIN UNNEST(${findings.finding__containers}) as findings__finding__containers ;;
      relationship: one_to_many
    }
    join: findings__finding__compliances__ids {
      view_label: "Findings: Finding Compliances Ids"
      sql: LEFT JOIN UNNEST(${findings.finding__compliances__ids}) as findings__finding__compliances__ids ;;
      relationship: one_to_many
    }
    join: findings__finding__indicator__domains {
      view_label: "Findings: Finding Indicator Domains"
      sql: LEFT JOIN UNNEST(${findings.finding__indicator__domains}) as findings__finding__indicator__domains ;;
      relationship: one_to_many
    }
    join: findings__finding__iam_bindings {
      view_label: "Findings: Finding Iam Bindings"
      sql: LEFT JOIN UNNEST(${findings.finding__iam_bindings}) as findings__finding__iam_bindings ;;
      relationship: one_to_many
    }
    join: findings__finding__database__grantees {
      view_label: "Findings: Finding Database Grantees"
      sql: LEFT JOIN UNNEST(${findings.finding__database__grantees}) as findings__finding__database__grantees ;;
      relationship: one_to_many
    }
    join: findings__finding__org_policies {
      view_label: "Findings: Finding Org Policies"
      sql: LEFT JOIN UNNEST(${findings.finding__org_policies}) as findings__finding__org_policies ;;
      relationship: one_to_many
    }
    join: findings__finding__kubernetes__pods {
      view_label: "Findings: Finding Kubernetes Pods"
      sql: LEFT JOIN UNNEST(${findings.finding__kubernetes__pods}) as findings__finding__kubernetes__pods ;;
      relationship: one_to_many
    }
    join: findings__finding__security_marks {
      view_label: "Findings: Finding Security Marks"
      sql: LEFT JOIN UNNEST(${findings.finding__security_marks}) as findings__finding__security_marks ;;
      relationship: one_to_many
    }
    join: findings__finding__kubernetes__roles {
      view_label: "Findings: Finding Kubernetes Roles"
      sql: LEFT JOIN UNNEST(${findings.finding__kubernetes__roles}) as findings__finding__kubernetes__roles ;;
      relationship: one_to_many
    }
    join: findings__finding__load_balancers {
      view_label: "Findings: Finding Load Balancers"
      sql: LEFT JOIN UNNEST(${findings.finding__load_balancers}) as findings__finding__load_balancers ;;
      relationship: one_to_many
    }
    join: findings__finding__compliances {
      view_label: "Findings: Finding Compliances"
      sql: LEFT JOIN UNNEST(${findings.finding__compliances}) as findings__finding__compliances ;;
      relationship: one_to_many
    }
    join: findings__finding__connections {
      view_label: "Findings: Finding Connections"
      sql: LEFT JOIN UNNEST(${findings.finding__connections}) as findings__finding__connections ;;
      relationship: one_to_many
    }
    join: findings__finding__kubernetes__nodes {
      view_label: "Findings: Finding Kubernetes Nodes"
      sql: LEFT JOIN UNNEST(${findings.finding__kubernetes__nodes}) as findings__finding__kubernetes__nodes ;;
      relationship: one_to_many
    }
    join: findings__finding__kubernetes__objects {
      view_label: "Findings: Finding Kubernetes Objects"
      sql: LEFT JOIN UNNEST(${findings.finding__kubernetes__objects}) as findings__finding__kubernetes__objects ;;
      relationship: one_to_many
    }
    join: findings__finding__source_properties {
      view_label: "Findings: Finding Source Properties"
      sql: LEFT JOIN UNNEST(${findings.finding__source_properties}) as findings__finding__source_properties ;;
      relationship: one_to_many
    }
    join: findings__finding__contacts {
      view_label: "Findings: Finding Contacts"
      sql: LEFT JOIN UNNEST(${findings.finding__contacts}) as findings__finding__contacts ;;
      relationship: one_to_many
    }
    join: findings__finding__indicator__ip_addresses {
      view_label: "Findings: Finding Indicator Ip Addresses"
      sql: LEFT JOIN UNNEST(${findings.finding__indicator__ip_addresses}) as findings__finding__indicator__ip_addresses ;;
      relationship: one_to_many
    }
    join: findings__finding__kubernetes__bindings {
      view_label: "Findings: Finding Kubernetes Bindings"
      sql: LEFT JOIN UNNEST(${findings.finding__kubernetes__bindings}) as findings__finding__kubernetes__bindings ;;
      relationship: one_to_many
    }
    join: findings__finding__containers__labels {
      view_label: "Findings: Finding Containers Labels"
      sql: LEFT JOIN UNNEST(${findings__finding__containers.labels}) as findings__finding__containers__labels ;;
      relationship: one_to_many
    }
    join: findings__finding__processes__library_paths {
      view_label: "Findings: Finding Processes Library Paths"
      sql: LEFT JOIN UNNEST(${findings__finding__processes.library_paths}) as findings__finding__processes__library_paths ;;
      relationship: one_to_many
    }
    join: findings__resource__folders {
      view_label: "Findings: Resource Folders"
      sql: LEFT JOIN UNNEST(${findings.resource__folders}) as findings__resource__folders ;;
      relationship: one_to_many
    }
    join: findings__finding__processes__libraries {
      view_label: "Findings: Finding Processes Libraries"
      sql: LEFT JOIN UNNEST(${findings__finding__processes.libraries}) as findings__finding__processes__libraries ;;
      relationship: one_to_many
    }
    join: findings__finding__exfiltration__sources {
      view_label: "Findings: Finding Exfiltration Sources"
      sql: LEFT JOIN UNNEST(${findings.finding__exfiltration__sources}) as findings__finding__exfiltration__sources ;;
      relationship: one_to_many
    }
    join: findings__finding__exfiltration__targets {
      view_label: "Findings: Finding Exfiltration Targets"
      sql: LEFT JOIN UNNEST(${findings.finding__exfiltration__targets}) as findings__finding__exfiltration__targets ;;
      relationship: one_to_many
    }
    join: findings__finding__ip_rules__source_ip_ranges {
      view_label: "Findings: Finding Ip Rules Source Ip Ranges"
      sql: LEFT JOIN UNNEST(${findings.finding__ip_rules__source_ip_ranges}) as findings__finding__ip_rules__source_ip_ranges ;;
      relationship: one_to_many
    }
    join: findings__finding__ip_rules__exposed_services {
      view_label: "Findings: Finding Ip Rules Exposed Services"
      sql: LEFT JOIN UNNEST(${findings.finding__ip_rules__exposed_services}) as findings__finding__ip_rules__exposed_services ;;
      relationship: one_to_many
    }
    join: findings__finding__kubernetes__node_pools {
      view_label: "Findings: Finding Kubernetes Node Pools"
      sql: LEFT JOIN UNNEST(${findings.finding__kubernetes__node_pools}) as findings__finding__kubernetes__node_pools ;;
      relationship: one_to_many
    }
    join: findings__finding__kubernetes__pods__labels {
      view_label: "Findings: Finding Kubernetes Pods Labels"
      sql: LEFT JOIN UNNEST(${findings__finding__kubernetes__pods.labels}) as findings__finding__kubernetes__pods__labels ;;
      relationship: one_to_many
    }
    join: findings__finding__processes__env_variables {
      view_label: "Findings: Finding Processes Env Variables"
      sql: LEFT JOIN UNNEST(${findings__finding__processes.env_variables}) as findings__finding__processes__env_variables ;;
      relationship: one_to_many
    }
    join: findings__finding__org_policy_constraints {
      view_label: "Findings: Finding Org Policy Constraints"
      sql: LEFT JOIN UNNEST(${findings.finding__org_policy_constraints}) as findings__finding__org_policy_constraints ;;
      relationship: one_to_many
    }
    join: findings__finding__kubernetes__access_reviews {
      view_label: "Findings: Finding Kubernetes Access Reviews"
      sql: LEFT JOIN UNNEST(${findings.finding__kubernetes__access_reviews}) as findings__finding__kubernetes__access_reviews ;;
      relationship: one_to_many
    }
    join: findings__finding__kubernetes__pods__containers {
      view_label: "Findings: Finding Kubernetes Pods Containers"
      sql: LEFT JOIN UNNEST(${findings__finding__kubernetes__pods.containers}) as findings__finding__kubernetes__pods__containers ;;
      relationship: one_to_many
    }
    join: findings__finding__ip_rules__destination_ip_ranges {
      view_label: "Findings: Finding Ip Rules Destination Ip Ranges"
      sql: LEFT JOIN UNNEST(${findings.finding__ip_rules__destination_ip_ranges}) as findings__finding__ip_rules__destination_ip_ranges ;;
      relationship: one_to_many
    }
    join: findings__finding__kubernetes__bindings__subjects {
      view_label: "Findings: Finding Kubernetes Bindings Subjects"
      sql: LEFT JOIN UNNEST(${findings__finding__kubernetes__bindings.subjects}) as findings__finding__kubernetes__bindings__subjects ;;
      relationship: one_to_many
    }
    join: findings__finding__exfiltration__sources__components {
      view_label: "Findings: Finding Exfiltration Sources Components"
      sql: LEFT JOIN UNNEST(${findings__finding__exfiltration__sources.components}) as findings__finding__exfiltration__sources__components ;;
      relationship: one_to_many
    }
    join: findings__finding__exfiltration__targets__components {
      view_label: "Findings: Finding Exfiltration Targets Components"
      sql: LEFT JOIN UNNEST(${findings__finding__exfiltration__targets.components}) as findings__finding__exfiltration__targets__components ;;
      relationship: one_to_many
    }
    join: findings__finding__mitre_attack__additional_tactics {
      view_label: "Findings: Finding Mitre Attack Additional Tactics"
      sql: LEFT JOIN UNNEST(${findings.finding__mitre_attack__additional_tactics}) as findings__finding__mitre_attack__additional_tactics ;;
      relationship: one_to_many
    }
    join: findings__finding__mitre_attack__primary_techniques {
      view_label: "Findings: Finding Mitre Attack Primary Techniques"
      sql: LEFT JOIN UNNEST(${findings.finding__mitre_attack__primary_techniques}) as findings__finding__mitre_attack__primary_techniques ;;
      relationship: one_to_many
    }
    join: findings__finding__kubernetes__node_pools__nodes {
      view_label: "Findings: Finding Kubernetes Node Pools Nodes"
      sql: LEFT JOIN UNNEST(${findings__finding__kubernetes__node_pools.nodes}) as findings__finding__kubernetes__node_pools__nodes ;;
      relationship: one_to_many
    }
    join: findings__finding__vulnerability__cve__references {
      view_label: "Findings: Finding Vulnerability Cve References"
      sql: LEFT JOIN UNNEST(${findings.finding__vulnerability__cve__references}) as findings__finding__vulnerability__cve__references ;;
      relationship: one_to_many
    }
    join: findings__finding__kubernetes__objects__containers {
      view_label: "Findings: Finding Kubernetes Objects Containers"
      sql: LEFT JOIN UNNEST(${findings__finding__kubernetes__objects.containers}) as findings__finding__kubernetes__objects__containers ;;
      relationship: one_to_many
    }
    join: findings__finding__ip_rules__denied__ip_rules {
      view_label: "Findings: Finding Ip Rules Denied Ip Rules"
      sql: LEFT JOIN UNNEST(${findings.finding__ip_rules__denied__ip_rules}) as findings__finding__ip_rules__denied__ip_rules ;;
      relationship: one_to_many
    }
    join: findings__finding__backup_disaster_recovery__policies {
      view_label: "Findings: Finding Backup Disaster Recovery Policies"
      sql: LEFT JOIN UNNEST(${findings.finding__backup_disaster_recovery__policies}) as findings__finding__backup_disaster_recovery__policies ;;
      relationship: one_to_many
    }
    join: findings__finding__mitre_attack__additional_techniques {
      view_label: "Findings: Finding Mitre Attack Additional Techniques"
      sql: LEFT JOIN UNNEST(${findings.finding__mitre_attack__additional_techniques}) as findings__finding__mitre_attack__additional_techniques ;;
      relationship: one_to_many
    }
    join: findings__finding__ip_rules__allowed__ip_rules {
      view_label: "Findings: Finding Ip Rules Allowed Ip Rules"
      sql: LEFT JOIN UNNEST(${findings.finding__ip_rules__allowed__ip_rules}) as findings__finding__ip_rules__allowed__ip_rules ;;
      relationship: one_to_many
    }
    join: findings__finding__backup_disaster_recovery__applications {
      view_label: "Findings: Finding Backup Disaster Recovery Applications"
      sql: LEFT JOIN UNNEST(${findings.finding__backup_disaster_recovery__applications}) as findings__finding__backup_disaster_recovery__applications ;;
      relationship: one_to_many
    }
    join: findings__finding__kubernetes__pods__containers__labels {
      view_label: "Findings: Finding Kubernetes Pods Containers Labels"
      sql: LEFT JOIN UNNEST(${findings__finding__kubernetes__pods__containers.labels}) as findings__finding__kubernetes__pods__containers__labels ;;
      relationship: one_to_many
    }
    join: findings__finding__backup_disaster_recovery__policy_options {
      view_label: "Findings: Finding Backup Disaster Recovery Policy Options"
      sql: LEFT JOIN UNNEST(${findings.finding__backup_disaster_recovery__policy_options}) as findings__finding__backup_disaster_recovery__policy_options ;;
      relationship: one_to_many
    }
    join: findings__finding__contacts__contact_details__contacts {
      view_label: "Findings: Finding Contacts Contact Details Contacts"
      sql: LEFT JOIN UNNEST(${findings__finding__contacts.contact_details__contacts}) as findings__finding__contacts__contact_details__contacts ;;
      relationship: one_to_many
    }
    join: findings__finding__ip_rules__denied__ip_rules__port_ranges {
      view_label: "Findings: Finding Ip Rules Denied Ip Rules Port Ranges"
      sql: LEFT JOIN UNNEST(${findings__finding__ip_rules__denied__ip_rules.port_ranges}) as findings__finding__ip_rules__denied__ip_rules__port_ranges ;;
      relationship: one_to_many
    }
    join: findings__finding__kubernetes__objects__containers__labels {
      view_label: "Findings: Finding Kubernetes Objects Containers Labels"
      sql: LEFT JOIN UNNEST(${findings__finding__kubernetes__objects__containers.labels}) as findings__finding__kubernetes__objects__containers__labels ;;
      relationship: one_to_many
    }
    join: findings__finding__ip_rules__allowed__ip_rules__port_ranges {
      view_label: "Findings: Finding Ip Rules Allowed Ip Rules Port Ranges"
      sql: LEFT JOIN UNNEST(${findings__finding__ip_rules__allowed__ip_rules.port_ranges}) as findings__finding__ip_rules__allowed__ip_rules__port_ranges ;;
      relationship: one_to_many
    }
    join: findings__finding__indicator__signatures {
      view_label: "Findings: Finding Indicator Signatures"
      sql: LEFT JOIN UNNEST(${findings.finding__indicator__signatures}) as findings__finding__indicator__signatures ;;
      relationship: one_to_many
    }
    join: findings__finding__access__service_account_delegation_info {
      view_label: "Findings: Finding Access Service Account Delegation Info"
      sql: LEFT JOIN UNNEST(${findings.finding__access__service_account_delegation_info}) as findings__finding__access__service_account_delegation_info ;;
      relationship: one_to_many
    }
    join: findings__finding__indicator__signatures__memory_hash_signature__detections {
      view_label: "Findings: Finding Indicator Signatures Memory Hash Signature Detections"
      sql: LEFT JOIN UNNEST(${findings__finding__indicator__signatures.memory_hash_signature__detections}) as findings__finding__indicator__signatures__memory_hash_signature__detections ;;
      relationship: one_to_many
    }
}
view: findings {
  sql_table_name: `prj-b-seed-55f0.scc_export.findings` ;;
  drill_fields: [finding_id]

  dimension: finding_id {
    primary_key: yes
    type: string
    sql: ${TABLE}.finding_id ;;
  }
  dimension_group: event_time {
    type: time
    timeframes: [raw, time, date, week, month, quarter, year]
    sql: ${TABLE}.event_time ;;
  }
  dimension: finding__access__caller_ip {
    type: string
    sql: ${TABLE}.finding.access.caller_ip ;;
    group_label: "Finding Access"
    group_item_label: "Caller IP"
  }
  dimension: finding__access__caller_ip_geo__region_code {
    type: string
    sql: ${TABLE}.finding.access.caller_ip_geo.region_code ;;
    group_label: "Finding Access Caller IP Geo"
    group_item_label: "Region Code"
  }
  dimension: finding__access__method_name {
    type: string
    sql: ${TABLE}.finding.access.method_name ;;
    group_label: "Finding Access"
    group_item_label: "Method Name"
  }
  dimension: finding__access__principal_email {
    type: string
    sql: ${TABLE}.finding.access.principal_email ;;
    group_label: "Finding Access"
    group_item_label: "Principal Email"
  }
  dimension: finding__access__principal_subject {
    type: string
    sql: ${TABLE}.finding.access.principal_subject ;;
    group_label: "Finding Access"
    group_item_label: "Principal Subject"
  }
  dimension: finding__access__service_account_delegation_info {
    hidden: yes
    sql: ${TABLE}.finding.access.service_account_delegation_info ;;
    group_label: "Finding Access"
    group_item_label: "Service Account Delegation Info"
  }
  dimension: finding__access__service_account_key_name {
    type: string
    sql: ${TABLE}.finding.access.service_account_key_name ;;
    group_label: "Finding Access"
    group_item_label: "Service Account Key Name"
  }
  dimension: finding__access__service_name {
    type: string
    sql: ${TABLE}.finding.access.service_name ;;
    group_label: "Finding Access"
    group_item_label: "Service Name"
  }
  dimension: finding__access__user_agent {
    type: string
    sql: ${TABLE}.finding.access.user_agent ;;
    group_label: "Finding Access"
    group_item_label: "User Agent"
  }
  dimension: finding__access__user_agent_family {
    type: string
    sql: ${TABLE}.finding.access.user_agent_family ;;
    group_label: "Finding Access"
    group_item_label: "User Agent Family"
  }
  dimension: finding__access__user_name {
    type: string
    sql: ${TABLE}.finding.access.user_name ;;
    group_label: "Finding Access"
    group_item_label: "User Name"
  }
  dimension: finding__attack_exposure__attack_exposure_result {
    type: string
    sql: ${TABLE}.finding.attack_exposure.attack_exposure_result ;;
    group_label: "Finding Attack Exposure"
    group_item_label: "Attack Exposure Result"
  }
  dimension: finding__attack_exposure__exposed_high_value_resources_count {
    type: number
    sql: ${TABLE}.finding.attack_exposure.exposed_high_value_resources_count ;;
    group_label: "Finding Attack Exposure"
    group_item_label: "Exposed High Value Resources Count"
  }
  dimension: finding__attack_exposure__exposed_low_value_resources_count {
    type: number
    sql: ${TABLE}.finding.attack_exposure.exposed_low_value_resources_count ;;
    group_label: "Finding Attack Exposure"
    group_item_label: "Exposed Low Value Resources Count"
  }
  dimension: finding__attack_exposure__exposed_medium_value_resources_count {
    type: number
    sql: ${TABLE}.finding.attack_exposure.exposed_medium_value_resources_count ;;
    group_label: "Finding Attack Exposure"
    group_item_label: "Exposed Medium Value Resources Count"
  }
  dimension_group: finding__attack_exposure__latest_calculation {
    type: time
    timeframes: [raw, time, date, week, month, quarter, year]
    sql: ${TABLE}.finding.attack_exposure.latest_calculation_time ;;
  }
  dimension: finding__attack_exposure__score {
    type: number
    sql: ${TABLE}.finding.attack_exposure.score ;;
    group_label: "Finding Attack Exposure"
    group_item_label: "Score"
  }
  dimension: finding__attack_exposure__state {
    type: string
    sql: ${TABLE}.finding.attack_exposure.state ;;
    group_label: "Finding Attack Exposure"
    group_item_label: "State"
  }
  dimension: finding__backup_disaster_recovery__appliance {
    type: string
    sql: ${TABLE}.finding.backup_disaster_recovery.appliance ;;
    group_label: "Finding Backup Disaster Recovery"
    group_item_label: "Appliance"
  }
  dimension: finding__backup_disaster_recovery__applications {
    hidden: yes
    sql: ${TABLE}.finding.backup_disaster_recovery.applications ;;
    group_label: "Finding Backup Disaster Recovery"
    group_item_label: "Applications"
  }
  dimension_group: finding__backup_disaster_recovery__backup_create {
    type: time
    timeframes: [raw, time, date, week, month, quarter, year]
    sql: ${TABLE}.finding.backup_disaster_recovery.backup_create_time ;;
  }
  dimension: finding__backup_disaster_recovery__backup_template {
    type: string
    sql: ${TABLE}.finding.backup_disaster_recovery.backup_template ;;
    group_label: "Finding Backup Disaster Recovery"
    group_item_label: "Backup Template"
  }
  dimension: finding__backup_disaster_recovery__backup_type {
    type: string
    sql: ${TABLE}.finding.backup_disaster_recovery.backup_type ;;
    group_label: "Finding Backup Disaster Recovery"
    group_item_label: "Backup Type"
  }
  dimension: finding__backup_disaster_recovery__host {
    type: string
    sql: ${TABLE}.finding.backup_disaster_recovery.host ;;
    group_label: "Finding Backup Disaster Recovery"
    group_item_label: "Host"
  }
  dimension: finding__backup_disaster_recovery__policies {
    hidden: yes
    sql: ${TABLE}.finding.backup_disaster_recovery.policies ;;
    group_label: "Finding Backup Disaster Recovery"
    group_item_label: "Policies"
  }
  dimension: finding__backup_disaster_recovery__policy_options {
    hidden: yes
    sql: ${TABLE}.finding.backup_disaster_recovery.policy_options ;;
    group_label: "Finding Backup Disaster Recovery"
    group_item_label: "Policy Options"
  }
  dimension: finding__backup_disaster_recovery__profile {
    type: string
    sql: ${TABLE}.finding.backup_disaster_recovery.profile ;;
    group_label: "Finding Backup Disaster Recovery"
    group_item_label: "Profile"
  }
  dimension: finding__backup_disaster_recovery__storage_pool {
    type: string
    sql: ${TABLE}.finding.backup_disaster_recovery.storage_pool ;;
    group_label: "Finding Backup Disaster Recovery"
    group_item_label: "Storage Pool"
  }
  dimension: finding__canonical_name {
    type: string
    sql: ${TABLE}.finding.canonical_name ;;
    group_label: "Finding"
    group_item_label: "Canonical Name"
  }
  dimension: finding__category {
    type: string
    sql: ${TABLE}.finding.category ;;
    group_label: "Finding"
    group_item_label: "Category"
  }
  dimension: finding__cloud_armor__adaptive_protection__confidence {
    type: number
    sql: ${TABLE}.finding.cloud_armor.adaptive_protection.confidence ;;
    group_label: "Finding Cloud Armor Adaptive Protection"
    group_item_label: "Confidence"
  }
  dimension: finding__cloud_armor__attack__classification {
    type: string
    sql: ${TABLE}.finding.cloud_armor.attack.classification ;;
    group_label: "Finding Cloud Armor Attack"
    group_item_label: "Classification"
  }
  dimension: finding__cloud_armor__attack__volume_bps {
    type: number
    sql: ${TABLE}.finding.cloud_armor.attack.volume_bps ;;
    group_label: "Finding Cloud Armor Attack"
    group_item_label: "Volume Bps"
  }
  dimension: finding__cloud_armor__attack__volume_pps {
    type: number
    sql: ${TABLE}.finding.cloud_armor.attack.volume_pps ;;
    group_label: "Finding Cloud Armor Attack"
    group_item_label: "Volume Pps"
  }
  dimension: finding__cloud_armor__requests__long_term_allowed {
    type: number
    sql: ${TABLE}.finding.cloud_armor.requests.long_term_allowed ;;
    group_label: "Finding Cloud Armor Requests"
    group_item_label: "Long Term Allowed"
  }
  dimension: finding__cloud_armor__requests__long_term_denied {
    type: number
    sql: ${TABLE}.finding.cloud_armor.requests.long_term_denied ;;
    group_label: "Finding Cloud Armor Requests"
    group_item_label: "Long Term Denied"
  }
  dimension: finding__cloud_armor__requests__ratio {
    type: number
    sql: ${TABLE}.finding.cloud_armor.requests.ratio ;;
    group_label: "Finding Cloud Armor Requests"
    group_item_label: "Ratio"
  }
  dimension: finding__cloud_armor__requests__short_term_allowed {
    type: number
    sql: ${TABLE}.finding.cloud_armor.requests.short_term_allowed ;;
    group_label: "Finding Cloud Armor Requests"
    group_item_label: "Short Term Allowed"
  }
  dimension: finding__cloud_armor__security_policy__name {
    type: string
    sql: ${TABLE}.finding.cloud_armor.security_policy.name ;;
    group_label: "Finding Cloud Armor Security Policy"
    group_item_label: "Name"
  }
  dimension: finding__cloud_armor__security_policy__preview {
    type: yesno
    sql: ${TABLE}.finding.cloud_armor.security_policy.preview ;;
    group_label: "Finding Cloud Armor Security Policy"
    group_item_label: "Preview"
  }
  dimension: finding__cloud_armor__security_policy__type {
    type: string
    sql: ${TABLE}.finding.cloud_armor.security_policy.type ;;
    group_label: "Finding Cloud Armor Security Policy"
    group_item_label: "Type"
  }
  dimension: finding__cloud_armor__threat_vector {
    type: string
    sql: ${TABLE}.finding.cloud_armor.threat_vector ;;
    group_label: "Finding Cloud Armor"
    group_item_label: "Threat Vector"
  }
  dimension: finding__cloud_dlp_data_profile__data_profile {
    type: string
    sql: ${TABLE}.finding.cloud_dlp_data_profile.data_profile ;;
    group_label: "Finding Cloud Dlp Data Profile"
    group_item_label: "Data Profile"
  }
  dimension: finding__cloud_dlp_data_profile__parent_type {
    type: string
    sql: ${TABLE}.finding.cloud_dlp_data_profile.parent_type ;;
    group_label: "Finding Cloud Dlp Data Profile"
    group_item_label: "Parent Type"
  }
  dimension: finding__cloud_dlp_inspection__full_scan {
    type: yesno
    sql: ${TABLE}.finding.cloud_dlp_inspection.full_scan ;;
    group_label: "Finding Cloud Dlp Inspection"
    group_item_label: "Full Scan"
  }
  dimension: finding__cloud_dlp_inspection__info_type {
    type: string
    sql: ${TABLE}.finding.cloud_dlp_inspection.info_type ;;
    group_label: "Finding Cloud Dlp Inspection"
    group_item_label: "Info Type"
  }
  dimension: finding__cloud_dlp_inspection__info_type_count {
    type: number
    sql: ${TABLE}.finding.cloud_dlp_inspection.info_type_count ;;
    group_label: "Finding Cloud Dlp Inspection"
    group_item_label: "Info Type Count"
  }
  dimension: finding__cloud_dlp_inspection__inspect_job {
    type: string
    sql: ${TABLE}.finding.cloud_dlp_inspection.inspect_job ;;
    group_label: "Finding Cloud Dlp Inspection"
    group_item_label: "Inspect Job"
  }
  dimension: finding__compliances {
    hidden: yes
    sql: ${TABLE}.finding.compliances ;;
    group_label: "Finding"
    group_item_label: "Compliances"
  }
  dimension: finding__compliances__ids {
    hidden: yes
    sql: ${TABLE}.finding.compliances.ids ;;
    group_label: "Finding Compliances"
    group_item_label: "Ids"
  }
  dimension: finding__connections {
    hidden: yes
    sql: ${TABLE}.finding.connections ;;
    group_label: "Finding"
    group_item_label: "Connections"
  }
  dimension: finding__contacts {
    hidden: yes
    sql: ${TABLE}.finding.contacts ;;
    group_label: "Finding"
    group_item_label: "Contacts"
  }
  dimension: finding__containers {
    hidden: yes
    sql: ${TABLE}.finding.containers ;;
    group_label: "Finding"
    group_item_label: "Containers"
  }
  dimension_group: finding__create {
    type: time
    timeframes: [raw, time, date, week, month, quarter, year]
    sql: ${TABLE}.finding.create_time ;;
  }
  dimension: finding__database__display_name {
    type: string
    sql: ${TABLE}.finding.database.display_name ;;
    group_label: "Finding Database"
    group_item_label: "Display Name"
  }
  dimension: finding__database__grantees {
    hidden: yes
    sql: ${TABLE}.finding.database.grantees ;;
    group_label: "Finding Database"
    group_item_label: "Grantees"
  }
  dimension: finding__database__name {
    type: string
    sql: ${TABLE}.finding.database.name ;;
    group_label: "Finding Database"
    group_item_label: "Name"
  }
  dimension: finding__database__query {
    type: string
    sql: ${TABLE}.finding.database.query ;;
    group_label: "Finding Database"
    group_item_label: "Query"
  }
  dimension: finding__database__user_name {
    type: string
    sql: ${TABLE}.finding.database.user_name ;;
    group_label: "Finding Database"
    group_item_label: "User Name"
  }
  dimension: finding__database__version {
    type: string
    sql: ${TABLE}.finding.database.version ;;
    group_label: "Finding Database"
    group_item_label: "Version"
  }
  dimension: finding__description {
    type: string
    sql: ${TABLE}.finding.description ;;
    group_label: "Finding"
    group_item_label: "Description"
  }
  dimension_group: finding__event {
    type: time
    timeframes: [raw, time, date, week, month, quarter, year]
    sql: ${TABLE}.finding.event_time ;;
  }
  dimension: finding__exfiltration__sources {
    hidden: yes
    sql: ${TABLE}.finding.exfiltration.sources ;;
    group_label: "Finding Exfiltration"
    group_item_label: "Sources"
  }
  dimension: finding__exfiltration__targets {
    hidden: yes
    sql: ${TABLE}.finding.exfiltration.targets ;;
    group_label: "Finding Exfiltration"
    group_item_label: "Targets"
  }
  dimension: finding__external_uri {
    type: string
    sql: ${TABLE}.finding.external_uri ;;
    group_label: "Finding"
    group_item_label: "External URI"
  }
  dimension: finding__files {
    hidden: yes
    sql: ${TABLE}.finding.files ;;
    group_label: "Finding"
    group_item_label: "Files"
  }
  dimension: finding__finding_class {
    type: string
    sql: ${TABLE}.finding.finding_class ;;
    group_label: "Finding"
    group_item_label: "Finding Class"
  }
  dimension: finding__iam_bindings {
    hidden: yes
    sql: ${TABLE}.finding.iam_bindings ;;
    group_label: "Finding"
    group_item_label: "Iam Bindings"
  }
  dimension: finding__indicator__domains {
    hidden: yes
    sql: ${TABLE}.finding.indicator.domains ;;
    group_label: "Finding Indicator"
    group_item_label: "Domains"
  }
  dimension: finding__indicator__ip_addresses {
    hidden: yes
    sql: ${TABLE}.finding.indicator.ip_addresses ;;
    group_label: "Finding Indicator"
    group_item_label: "IP Addresses"
  }
  dimension: finding__indicator__signatures {
    hidden: yes
    sql: ${TABLE}.finding.indicator.signatures ;;
    group_label: "Finding Indicator"
    group_item_label: "Signatures"
  }
  dimension: finding__indicator__uris {
    hidden: yes
    sql: ${TABLE}.finding.indicator.uris ;;
    group_label: "Finding Indicator"
    group_item_label: "Uris"
  }
  dimension: finding__ip_rules__allowed__ip_rules {
    hidden: yes
    sql: ${TABLE}.finding.ip_rules.allowed.ip_rules ;;
    group_label: "Finding IP Rules Allowed"
    group_item_label: "IP Rules"
  }
  dimension: finding__ip_rules__denied__ip_rules {
    hidden: yes
    sql: ${TABLE}.finding.ip_rules.denied.ip_rules ;;
    group_label: "Finding IP Rules Denied"
    group_item_label: "IP Rules"
  }
  dimension: finding__ip_rules__destination_ip_ranges {
    hidden: yes
    sql: ${TABLE}.finding.ip_rules.destination_ip_ranges ;;
    group_label: "Finding IP Rules"
    group_item_label: "Destination IP Ranges"
  }
  dimension: finding__ip_rules__direction {
    type: string
    sql: ${TABLE}.finding.ip_rules.direction ;;
    group_label: "Finding IP Rules"
    group_item_label: "Direction"
  }
  dimension: finding__ip_rules__exposed_services {
    hidden: yes
    sql: ${TABLE}.finding.ip_rules.exposed_services ;;
    group_label: "Finding IP Rules"
    group_item_label: "Exposed Services"
  }
  dimension: finding__ip_rules__source_ip_ranges {
    hidden: yes
    sql: ${TABLE}.finding.ip_rules.source_ip_ranges ;;
    group_label: "Finding IP Rules"
    group_item_label: "Source IP Ranges"
  }
  dimension: finding__kernel_rootkit__name {
    type: string
    sql: ${TABLE}.finding.kernel_rootkit.name ;;
    group_label: "Finding Kernel Rootkit"
    group_item_label: "Name"
  }
  dimension: finding__kernel_rootkit__unexpected_code_modification {
    type: yesno
    sql: ${TABLE}.finding.kernel_rootkit.unexpected_code_modification ;;
    group_label: "Finding Kernel Rootkit"
    group_item_label: "Unexpected Code Modification"
  }
  dimension: finding__kernel_rootkit__unexpected_ftrace_handler {
    type: yesno
    sql: ${TABLE}.finding.kernel_rootkit.unexpected_ftrace_handler ;;
    group_label: "Finding Kernel Rootkit"
    group_item_label: "Unexpected Ftrace Handler"
  }
  dimension: finding__kernel_rootkit__unexpected_interrupt_handler {
    type: yesno
    sql: ${TABLE}.finding.kernel_rootkit.unexpected_interrupt_handler ;;
    group_label: "Finding Kernel Rootkit"
    group_item_label: "Unexpected Interrupt Handler"
  }
  dimension: finding__kernel_rootkit__unexpected_kernel_code_pages {
    type: yesno
    sql: ${TABLE}.finding.kernel_rootkit.unexpected_kernel_code_pages ;;
    group_label: "Finding Kernel Rootkit"
    group_item_label: "Unexpected Kernel Code Pages"
  }
  dimension: finding__kernel_rootkit__unexpected_kprobe_handler {
    type: yesno
    sql: ${TABLE}.finding.kernel_rootkit.unexpected_kprobe_handler ;;
    group_label: "Finding Kernel Rootkit"
    group_item_label: "Unexpected Kprobe Handler"
  }
  dimension: finding__kernel_rootkit__unexpected_processes_in_runqueue {
    type: yesno
    sql: ${TABLE}.finding.kernel_rootkit.unexpected_processes_in_runqueue ;;
    group_label: "Finding Kernel Rootkit"
    group_item_label: "Unexpected Processes In Runqueue"
  }
  dimension: finding__kernel_rootkit__unexpected_read_only_data_modification {
    type: yesno
    sql: ${TABLE}.finding.kernel_rootkit.unexpected_read_only_data_modification ;;
    group_label: "Finding Kernel Rootkit"
    group_item_label: "Unexpected Read Only Data Modification"
  }
  dimension: finding__kernel_rootkit__unexpected_system_call_handler {
    type: yesno
    sql: ${TABLE}.finding.kernel_rootkit.unexpected_system_call_handler ;;
    group_label: "Finding Kernel Rootkit"
    group_item_label: "Unexpected System Call Handler"
  }
  dimension: finding__kubernetes__access_reviews {
    hidden: yes
    sql: ${TABLE}.finding.kubernetes.access_reviews ;;
    group_label: "Finding Kubernetes"
    group_item_label: "Access Reviews"
  }
  dimension: finding__kubernetes__bindings {
    hidden: yes
    sql: ${TABLE}.finding.kubernetes.bindings ;;
    group_label: "Finding Kubernetes"
    group_item_label: "Bindings"
  }
  dimension: finding__kubernetes__node_pools {
    hidden: yes
    sql: ${TABLE}.finding.kubernetes.node_pools ;;
    group_label: "Finding Kubernetes"
    group_item_label: "Node Pools"
  }
  dimension: finding__kubernetes__nodes {
    hidden: yes
    sql: ${TABLE}.finding.kubernetes.nodes ;;
    group_label: "Finding Kubernetes"
    group_item_label: "Nodes"
  }
  dimension: finding__kubernetes__objects {
    hidden: yes
    sql: ${TABLE}.finding.kubernetes.objects ;;
    group_label: "Finding Kubernetes"
    group_item_label: "Objects"
  }
  dimension: finding__kubernetes__pods {
    hidden: yes
    sql: ${TABLE}.finding.kubernetes.pods ;;
    group_label: "Finding Kubernetes"
    group_item_label: "Pods"
  }
  dimension: finding__kubernetes__roles {
    hidden: yes
    sql: ${TABLE}.finding.kubernetes.roles ;;
    group_label: "Finding Kubernetes"
    group_item_label: "Roles"
  }
  dimension: finding__load_balancers {
    hidden: yes
    sql: ${TABLE}.finding.load_balancers ;;
    group_label: "Finding"
    group_item_label: "Load Balancers"
  }
  dimension: finding__mitre_attack__additional_tactics {
    hidden: yes
    sql: ${TABLE}.finding.mitre_attack.additional_tactics ;;
    group_label: "Finding Mitre Attack"
    group_item_label: "Additional Tactics"
  }
  dimension: finding__mitre_attack__additional_techniques {
    hidden: yes
    sql: ${TABLE}.finding.mitre_attack.additional_techniques ;;
    group_label: "Finding Mitre Attack"
    group_item_label: "Additional Techniques"
  }
  dimension: finding__mitre_attack__primary_tactic {
    type: string
    sql: ${TABLE}.finding.mitre_attack.primary_tactic ;;
    group_label: "Finding Mitre Attack"
    group_item_label: "Primary Tactic"
  }
  dimension: finding__mitre_attack__primary_techniques {
    hidden: yes
    sql: ${TABLE}.finding.mitre_attack.primary_techniques ;;
    group_label: "Finding Mitre Attack"
    group_item_label: "Primary Techniques"
  }
  dimension: finding__mitre_attack__version {
    type: string
    sql: ${TABLE}.finding.mitre_attack.version ;;
    group_label: "Finding Mitre Attack"
    group_item_label: "Version"
  }
  dimension: finding__module_name {
    type: string
    sql: ${TABLE}.finding.module_name ;;
    group_label: "Finding"
    group_item_label: "Module Name"
  }
  dimension: finding__mute {
    type: string
    sql: ${TABLE}.finding.mute ;;
    group_label: "Finding"
    group_item_label: "Mute"
  }
  dimension: finding__mute_initiator {
    type: string
    sql: ${TABLE}.finding.mute_initiator ;;
    group_label: "Finding"
    group_item_label: "Mute Initiator"
  }
  dimension_group: finding__mute_update {
    type: time
    timeframes: [raw, time, date, week, month, quarter, year]
    sql: ${TABLE}.finding.mute_update_time ;;
  }
  dimension: finding__name {
    type: string
    sql: ${TABLE}.finding.name ;;
    group_label: "Finding"
    group_item_label: "Name"
  }
  dimension: finding__next_steps {
    type: string
    sql: ${TABLE}.finding.next_steps ;;
    group_label: "Finding"
    group_item_label: "Next Steps"
  }
  dimension: finding__org_policies {
    hidden: yes
    sql: ${TABLE}.finding.org_policies ;;
    group_label: "Finding"
    group_item_label: "Org Policies"
  }
  dimension: finding__org_policy_constraints {
    hidden: yes
    sql: ${TABLE}.finding.org_policy_constraints ;;
    group_label: "Finding"
    group_item_label: "Org Policy Constraints"
  }
  dimension: finding__parent {
    type: string
    sql: ${TABLE}.finding.parent ;;
    group_label: "Finding"
    group_item_label: "Parent"
  }
  dimension: finding__parent_display_name {
    type: string
    sql: ${TABLE}.finding.parent_display_name ;;
    group_label: "Finding"
    group_item_label: "Parent Display Name"
  }
  dimension: finding__processes {
    hidden: yes
    sql: ${TABLE}.finding.processes ;;
    group_label: "Finding"
    group_item_label: "Processes"
  }
  dimension: finding__security_marks {
    hidden: yes
    sql: ${TABLE}.finding.security_marks ;;
    group_label: "Finding"
    group_item_label: "Security Marks"
  }
  dimension: finding__security_posture__changed_policy {
    type: string
    sql: ${TABLE}.finding.security_posture.changed_policy ;;
    group_label: "Finding Security Posture"
    group_item_label: "Changed Policy"
  }
  dimension: finding__security_posture__name {
    type: string
    sql: ${TABLE}.finding.security_posture.name ;;
    group_label: "Finding Security Posture"
    group_item_label: "Name"
  }
  dimension: finding__security_posture__posture_deployment {
    type: string
    sql: ${TABLE}.finding.security_posture.posture_deployment ;;
    group_label: "Finding Security Posture"
    group_item_label: "Posture Deployment"
  }
  dimension: finding__security_posture__posture_deployment_resource {
    type: string
    sql: ${TABLE}.finding.security_posture.posture_deployment_resource ;;
    group_label: "Finding Security Posture"
    group_item_label: "Posture Deployment Resource"
  }
  dimension: finding__security_posture__revision_id {
    type: string
    sql: ${TABLE}.finding.security_posture.revision_id ;;
    group_label: "Finding Security Posture"
    group_item_label: "Revision ID"
  }
  dimension: finding__severity {
    type: string
    sql: ${TABLE}.finding.severity ;;
    group_label: "Finding"
    group_item_label: "Severity"
  }
  dimension: finding__source_properties {
    hidden: yes
    sql: ${TABLE}.finding.source_properties ;;
    group_label: "Finding"
    group_item_label: "Source Properties"
  }
  dimension: finding__source_properties_json {
    type: string
    sql: ${TABLE}.finding.source_properties_json ;;
    group_label: "Finding"
    group_item_label: "Source Properties JSON"
  }
  dimension: finding__state {
    type: string
    sql: ${TABLE}.finding.state ;;
    group_label: "Finding"
    group_item_label: "State"
  }
  dimension: finding__vulnerability__cve__cvssv3__attack_complexity {
    type: string
    sql: ${TABLE}.finding.vulnerability.cve.cvssv3.attack_complexity ;;
    group_label: "Finding Vulnerability Cve Cvssv3"
    group_item_label: "Attack Complexity"
  }
  dimension: finding__vulnerability__cve__cvssv3__attack_vector {
    type: string
    sql: ${TABLE}.finding.vulnerability.cve.cvssv3.attack_vector ;;
    group_label: "Finding Vulnerability Cve Cvssv3"
    group_item_label: "Attack Vector"
  }
  dimension: finding__vulnerability__cve__cvssv3__availability_impact {
    type: string
    sql: ${TABLE}.finding.vulnerability.cve.cvssv3.availability_impact ;;
    group_label: "Finding Vulnerability Cve Cvssv3"
    group_item_label: "Availability Impact"
  }
  dimension: finding__vulnerability__cve__cvssv3__base_score {
    type: number
    sql: ${TABLE}.finding.vulnerability.cve.cvssv3.base_score ;;
    group_label: "Finding Vulnerability Cve Cvssv3"
    group_item_label: "Base Score"
  }
  dimension: finding__vulnerability__cve__cvssv3__confidentiality_impact {
    type: string
    sql: ${TABLE}.finding.vulnerability.cve.cvssv3.confidentiality_impact ;;
    group_label: "Finding Vulnerability Cve Cvssv3"
    group_item_label: "Confidentiality Impact"
  }
  dimension: finding__vulnerability__cve__cvssv3__integrity_impact {
    type: string
    sql: ${TABLE}.finding.vulnerability.cve.cvssv3.integrity_impact ;;
    group_label: "Finding Vulnerability Cve Cvssv3"
    group_item_label: "Integrity Impact"
  }
  dimension: finding__vulnerability__cve__cvssv3__privileges_required {
    type: string
    sql: ${TABLE}.finding.vulnerability.cve.cvssv3.privileges_required ;;
    group_label: "Finding Vulnerability Cve Cvssv3"
    group_item_label: "Privileges Required"
  }
  dimension: finding__vulnerability__cve__cvssv3__scope {
    type: string
    sql: ${TABLE}.finding.vulnerability.cve.cvssv3.scope ;;
    group_label: "Finding Vulnerability Cve Cvssv3"
    group_item_label: "Scope"
  }
  dimension: finding__vulnerability__cve__cvssv3__user_interaction {
    type: string
    sql: ${TABLE}.finding.vulnerability.cve.cvssv3.user_interaction ;;
    group_label: "Finding Vulnerability Cve Cvssv3"
    group_item_label: "User Interaction"
  }
  dimension: finding__vulnerability__cve__id {
    type: string
    sql: ${TABLE}.finding.vulnerability.cve.id ;;
    group_label: "Finding Vulnerability Cve"
    group_item_label: "ID"
  }
  dimension: finding__vulnerability__cve__references {
    hidden: yes
    sql: ${TABLE}.finding.vulnerability.cve.references ;;
    group_label: "Finding Vulnerability Cve"
    group_item_label: "References"
  }
  dimension: finding__vulnerability__cve__upstream_fix_available {
    type: yesno
    sql: ${TABLE}.finding.vulnerability.cve.upstream_fix_available ;;
    group_label: "Finding Vulnerability Cve"
    group_item_label: "Upstream Fix Available"
  }
  dimension: resource__display_name {
    type: string
    sql: ${TABLE}.resource.display_name ;;
    group_label: "Resource"
    group_item_label: "Display Name"
  }
  dimension: resource__folders {
    hidden: yes
    sql: ${TABLE}.resource.folders ;;
    group_label: "Resource"
    group_item_label: "Folders"
  }
  dimension: resource__name {
    type: string
    sql: ${TABLE}.resource.name ;;
    group_label: "Resource"
    group_item_label: "Name"
  }
  dimension: resource__parent_display_name {
    type: string
    sql: ${TABLE}.resource.parent_display_name ;;
    group_label: "Resource"
    group_item_label: "Parent Display Name"
  }
  dimension: resource__parent_name {
    type: string
    sql: ${TABLE}.resource.parent_name ;;
    group_label: "Resource"
    group_item_label: "Parent Name"
  }
  dimension: resource__project_display_name {
    type: string
    sql: ${TABLE}.resource.project_display_name ;;
    group_label: "Resource"
    group_item_label: "Project Display Name"
  }
  dimension: resource__project_name {
    type: string
    sql: ${TABLE}.resource.project_name ;;
    group_label: "Resource"
    group_item_label: "Project Name"
  }
  dimension: resource__type {
    type: string
    sql: ${TABLE}.resource.type ;;
    group_label: "Resource"
    group_item_label: "Type"
  }
  dimension: source_id {
    type: string
    sql: ${TABLE}.source_id ;;
  }
  measure: count {
    type: count
    drill_fields: [detail*]
  }

  # ----- Sets of fields for drilling ------
  set: detail {
    fields: [
  finding_id,
  finding__name,
  resource__name,
  finding__module_name,
  resource__parent_name,
  resource__display_name,
  resource__project_name,
  finding__database__name,
  finding__canonical_name,
  finding__access__user_name,
  finding__access__method_name,
  finding__database__user_name,
  finding__kernel_rootkit__name,
  finding__access__service_name,
  finding__parent_display_name,
  resource__parent_display_name,
  resource__project_display_name,
  finding__security_posture__name,
  finding__database__display_name,
  finding__access__service_account_key_name,
  finding__cloud_armor__security_policy__name
  ]
  }

}

view: findings__finding__files {

  dimension: contents {
    type: string
    sql: ${TABLE}.contents ;;
  }
  dimension: hashed_size {
    type: number
    sql: ${TABLE}.hashed_size ;;
  }
  dimension: partially_hashed {
    type: yesno
    sql: ${TABLE}.partially_hashed ;;
  }
  dimension: path {
    type: string
    sql: ${TABLE}.path ;;
  }
  dimension: sha256 {
    type: string
    sql: ${TABLE}.sha256 ;;
  }
  dimension: size {
    type: number
    sql: ${TABLE}.size ;;
  }
}

view: findings__finding__processes {

  dimension: args {
    hidden: yes
    sql: ${TABLE}.args ;;
  }
  dimension: arguments_truncated {
    type: yesno
    sql: ${TABLE}.arguments_truncated ;;
  }
  dimension: binary__contents {
    type: string
    sql: ${TABLE}.binary.contents ;;
    group_label: "Binary"
    group_item_label: "Contents"
  }
  dimension: binary__hashed_size {
    type: number
    sql: ${TABLE}.binary.hashed_size ;;
    group_label: "Binary"
    group_item_label: "Hashed Size"
  }
  dimension: binary__partially_hashed {
    type: yesno
    sql: ${TABLE}.binary.partially_hashed ;;
    group_label: "Binary"
    group_item_label: "Partially Hashed"
  }
  dimension: binary__path {
    type: string
    sql: ${TABLE}.binary.path ;;
    group_label: "Binary"
    group_item_label: "Path"
  }
  dimension: binary__sha256 {
    type: string
    sql: ${TABLE}.binary.sha256 ;;
    group_label: "Binary"
    group_item_label: "Sha256"
  }
  dimension: binary__size {
    type: number
    sql: ${TABLE}.binary.size ;;
    group_label: "Binary"
    group_item_label: "Size"
  }
  dimension: binary_path {
    type: string
    sql: ${TABLE}.binary_path ;;
  }
  dimension: env_variables {
    hidden: yes
    sql: ${TABLE}.env_variables ;;
  }
  dimension: env_variables_truncated {
    type: yesno
    sql: ${TABLE}.env_variables_truncated ;;
  }
  dimension: libraries {
    hidden: yes
    sql: ${TABLE}.libraries ;;
  }
  dimension: library_paths {
    hidden: yes
    sql: ${TABLE}.library_paths ;;
  }
  dimension: name {
    type: string
    sql: ${TABLE}.name ;;
  }
  dimension: parent_pid {
    type: number
    value_format_name: id
    sql: ${TABLE}.parent_pid ;;
  }
  dimension: pid {
    type: number
    value_format_name: id
    sql: ${TABLE}.pid ;;
  }
  dimension: script__contents {
    type: string
    sql: ${TABLE}.script.contents ;;
    group_label: "Script"
    group_item_label: "Contents"
  }
  dimension: script__hashed_size {
    type: number
    sql: ${TABLE}.script.hashed_size ;;
    group_label: "Script"
    group_item_label: "Hashed Size"
  }
  dimension: script__partially_hashed {
    type: yesno
    sql: ${TABLE}.script.partially_hashed ;;
    group_label: "Script"
    group_item_label: "Partially Hashed"
  }
  dimension: script__path {
    type: string
    sql: ${TABLE}.script.path ;;
    group_label: "Script"
    group_item_label: "Path"
  }
  dimension: script__sha256 {
    type: string
    sql: ${TABLE}.script.sha256 ;;
    group_label: "Script"
    group_item_label: "Sha256"
  }
  dimension: script__size {
    type: number
    sql: ${TABLE}.script.size ;;
    group_label: "Script"
    group_item_label: "Size"
  }
}

view: findings__finding__indicator__uris {

  dimension: findings__finding__indicator__uris {
    type: string
    sql: findings__finding__indicator__uris ;;
  }
}

view: findings__finding__processes__args {

  dimension: findings__finding__processes__args {
    type: string
    sql: findings__finding__processes__args ;;
  }
}

view: findings__finding__containers {

  dimension_group: create {
    type: time
    timeframes: [raw, time, date, week, month, quarter, year]
    sql: ${TABLE}.create_time ;;
  }
  dimension: image_id {
    type: string
    sql: ${TABLE}.image_id ;;
  }
  dimension: labels {
    hidden: yes
    sql: ${TABLE}.labels ;;
  }
  dimension: name {
    type: string
    sql: ${TABLE}.name ;;
  }
  dimension: uri {
    type: string
    sql: ${TABLE}.uri ;;
  }
}

view: findings__finding__compliances__ids {

  dimension: findings__finding__compliances__ids {
    type: string
    sql: findings__finding__compliances__ids ;;
  }
}

view: findings__finding__indicator__domains {

  dimension: findings__finding__indicator__domains {
    type: string
    sql: findings__finding__indicator__domains ;;
  }
}

view: findings__finding__iam_bindings {

  dimension: action {
    type: string
    sql: ${TABLE}.action ;;
  }
  dimension: member {
    type: string
    sql: ${TABLE}.member ;;
  }
  dimension: role {
    type: string
    sql: ${TABLE}.role ;;
  }
}

view: findings__finding__database__grantees {

  dimension: findings__finding__database__grantees {
    type: string
    sql: findings__finding__database__grantees ;;
  }
}

view: findings__finding__org_policies {

  dimension: name {
    type: string
    sql: ${TABLE}.name ;;
  }
}

view: findings__finding__kubernetes__pods {

  dimension: containers {
    hidden: yes
    sql: ${TABLE}.containers ;;
  }
  dimension: labels {
    hidden: yes
    sql: ${TABLE}.labels ;;
  }
  dimension: name {
    type: string
    sql: ${TABLE}.name ;;
  }
  dimension: ns {
    type: string
    sql: ${TABLE}.ns ;;
  }
}

view: findings__finding__security_marks {

  dimension: key {
    type: string
    sql: ${TABLE}.key ;;
  }
  dimension: value {
    type: string
    sql: ${TABLE}.value ;;
  }
}

view: findings__finding__kubernetes__roles {

  dimension: kind {
    type: string
    sql: ${TABLE}.kind ;;
  }
  dimension: name {
    type: string
    sql: ${TABLE}.name ;;
  }
  dimension: ns {
    type: string
    sql: ${TABLE}.ns ;;
  }
}

view: findings__finding__load_balancers {

  dimension: name {
    type: string
    sql: ${TABLE}.name ;;
  }
}

view: findings__finding__compliances {

  dimension: standard {
    type: string
    sql: ${TABLE}.standard ;;
  }
  dimension: version {
    type: string
    sql: ${TABLE}.version ;;
  }
}

view: findings__finding__connections {

  dimension: destination_ip {
    type: string
    sql: ${TABLE}.destination_ip ;;
  }
  dimension: destination_port {
    type: number
    sql: ${TABLE}.destination_port ;;
  }
  dimension: protocol {
    type: string
    sql: ${TABLE}.protocol ;;
  }
  dimension: source_ip {
    type: string
    sql: ${TABLE}.source_ip ;;
  }
  dimension: source_port {
    type: number
    sql: ${TABLE}.source_port ;;
  }
}

view: findings__finding__kubernetes__nodes {

  dimension: name {
    type: string
    sql: ${TABLE}.name ;;
  }
}

view: findings__finding__kubernetes__objects {

  dimension: containers {
    hidden: yes
    sql: ${TABLE}.containers ;;
  }
  dimension: group {
    type: string
    sql: ${TABLE}.`group` ;;
  }
  dimension: kind {
    type: string
    sql: ${TABLE}.kind ;;
  }
  dimension: name {
    type: string
    sql: ${TABLE}.name ;;
  }
  dimension: ns {
    type: string
    sql: ${TABLE}.ns ;;
  }
}

view: findings__finding__source_properties {

  dimension: key {
    type: string
    sql: ${TABLE}.key ;;
  }
  dimension: value {
    type: string
    sql: ${TABLE}.value ;;
  }
}

view: findings__finding__contacts {

  dimension: contact_details__contacts {
    hidden: yes
    sql: ${TABLE}.contact_details.contacts ;;
    group_label: "Contact Details"
    group_item_label: "Contacts"
  }
  dimension: contact_type {
    type: string
    sql: ${TABLE}.contact_type ;;
  }
}

view: findings__finding__indicator__ip_addresses {

  dimension: findings__finding__indicator__ip_addresses {
    type: string
    sql: findings__finding__indicator__ip_addresses ;;
  }
}

view: findings__finding__kubernetes__bindings {

  dimension: name {
    type: string
    sql: ${TABLE}.name ;;
  }
  dimension: ns {
    type: string
    sql: ${TABLE}.ns ;;
  }
  dimension: role__kind {
    type: string
    sql: ${TABLE}.role.kind ;;
    group_label: "Role"
    group_item_label: "Kind"
  }
  dimension: role__name {
    type: string
    sql: ${TABLE}.role.name ;;
    group_label: "Role"
    group_item_label: "Name"
  }
  dimension: role__ns {
    type: string
    sql: ${TABLE}.role.ns ;;
    group_label: "Role"
    group_item_label: "Ns"
  }
  dimension: subjects {
    hidden: yes
    sql: ${TABLE}.subjects ;;
  }
}

view: findings__finding__containers__labels {

  dimension: name {
    type: string
    sql: ${TABLE}.name ;;
  }
  dimension: value {
    type: string
    sql: ${TABLE}.value ;;
  }
}

view: findings__finding__processes__library_paths {

  dimension: findings__finding__processes__library_paths {
    type: string
    sql: findings__finding__processes__library_paths ;;
  }
}

view: findings__resource__folders {

  dimension: resource_folder {
    type: string
    sql: ${TABLE}.resource_folder ;;
  }
  dimension: resource_folder_display_name {
    type: string
    sql: ${TABLE}.resource_folder_display_name ;;
  }
}

view: findings__finding__processes__libraries {

  dimension: contents {
    type: string
    sql: ${TABLE}.contents ;;
  }
  dimension: hashed_size {
    type: number
    sql: ${TABLE}.hashed_size ;;
  }
  dimension: partially_hashed {
    type: yesno
    sql: ${TABLE}.partially_hashed ;;
  }
  dimension: path {
    type: string
    sql: ${TABLE}.path ;;
  }
  dimension: sha256 {
    type: string
    sql: ${TABLE}.sha256 ;;
  }
  dimension: size {
    type: number
    sql: ${TABLE}.size ;;
  }
}

view: findings__finding__exfiltration__sources {

  dimension: components {
    hidden: yes
    sql: ${TABLE}.components ;;
  }
  dimension: name {
    type: string
    sql: ${TABLE}.name ;;
  }
}

view: findings__finding__exfiltration__targets {

  dimension: components {
    hidden: yes
    sql: ${TABLE}.components ;;
  }
  dimension: name {
    type: string
    sql: ${TABLE}.name ;;
  }
}

view: findings__finding__ip_rules__source_ip_ranges {

  dimension: findings__finding__ip_rules__source_ip_ranges {
    type: string
    sql: findings__finding__ip_rules__source_ip_ranges ;;
  }
}

view: findings__finding__ip_rules__exposed_services {

  dimension: findings__finding__ip_rules__exposed_services {
    type: string
    sql: findings__finding__ip_rules__exposed_services ;;
  }
}

view: findings__finding__kubernetes__node_pools {

  dimension: name {
    type: string
    sql: ${TABLE}.name ;;
  }
  dimension: nodes {
    hidden: yes
    sql: ${TABLE}.nodes ;;
  }
}

view: findings__finding__kubernetes__pods__labels {

  dimension: name {
    type: string
    sql: ${TABLE}.name ;;
  }
  dimension: value {
    type: string
    sql: ${TABLE}.value ;;
  }
}

view: findings__finding__processes__env_variables {

  dimension: name {
    type: string
    sql: ${TABLE}.name ;;
  }
  dimension: val {
    type: string
    sql: ${TABLE}.val ;;
  }
}

view: findings__finding__org_policy_constraints {

  dimension: name {
    type: string
    sql: ${TABLE}.name ;;
  }
}

view: findings__finding__kubernetes__access_reviews {

  dimension: group {
    type: string
    sql: ${TABLE}.`group` ;;
  }
  dimension: name {
    type: string
    sql: ${TABLE}.name ;;
  }
  dimension: ns {
    type: string
    sql: ${TABLE}.ns ;;
  }
  dimension: resource {
    type: string
    sql: ${TABLE}.resource ;;
  }
  dimension: subresource {
    type: string
    sql: ${TABLE}.subresource ;;
  }
  dimension: verb {
    type: string
    sql: ${TABLE}.verb ;;
  }
  dimension: version {
    type: string
    sql: ${TABLE}.version ;;
  }
}

view: findings__finding__kubernetes__pods__containers {

  dimension_group: create {
    type: time
    timeframes: [raw, time, date, week, month, quarter, year]
    sql: ${TABLE}.create_time ;;
  }
  dimension: image_id {
    type: string
    sql: ${TABLE}.image_id ;;
  }
  dimension: labels {
    hidden: yes
    sql: ${TABLE}.labels ;;
  }
  dimension: name {
    type: string
    sql: ${TABLE}.name ;;
  }
  dimension: uri {
    type: string
    sql: ${TABLE}.uri ;;
  }
}

view: findings__finding__ip_rules__destination_ip_ranges {

  dimension: findings__finding__ip_rules__destination_ip_ranges {
    type: string
    sql: findings__finding__ip_rules__destination_ip_ranges ;;
  }
}

view: findings__finding__kubernetes__bindings__subjects {

  dimension: kind {
    type: string
    sql: ${TABLE}.kind ;;
  }
  dimension: name {
    type: string
    sql: ${TABLE}.name ;;
  }
  dimension: ns {
    type: string
    sql: ${TABLE}.ns ;;
  }
}

view: findings__finding__exfiltration__sources__components {

  dimension: findings__finding__exfiltration__sources__components {
    type: string
    sql: findings__finding__exfiltration__sources__components ;;
  }
}

view: findings__finding__exfiltration__targets__components {

  dimension: findings__finding__exfiltration__targets__components {
    type: string
    sql: findings__finding__exfiltration__targets__components ;;
  }
}

view: findings__finding__mitre_attack__additional_tactics {

  dimension: findings__finding__mitre_attack__additional_tactics {
    type: string
    sql: findings__finding__mitre_attack__additional_tactics ;;
  }
}

view: findings__finding__mitre_attack__primary_techniques {

  dimension: findings__finding__mitre_attack__primary_techniques {
    type: string
    sql: findings__finding__mitre_attack__primary_techniques ;;
  }
}

view: findings__finding__kubernetes__node_pools__nodes {

  dimension: name {
    type: string
    sql: ${TABLE}.name ;;
  }
}

view: findings__finding__vulnerability__cve__references {

  dimension: source {
    type: string
    sql: ${TABLE}.source ;;
  }
  dimension: uri {
    type: string
    sql: ${TABLE}.uri ;;
  }
}

view: findings__finding__kubernetes__objects__containers {

  dimension_group: create {
    type: time
    timeframes: [raw, time, date, week, month, quarter, year]
    sql: ${TABLE}.create_time ;;
  }
  dimension: image_id {
    type: string
    sql: ${TABLE}.image_id ;;
  }
  dimension: labels {
    hidden: yes
    sql: ${TABLE}.labels ;;
  }
  dimension: name {
    type: string
    sql: ${TABLE}.name ;;
  }
  dimension: uri {
    type: string
    sql: ${TABLE}.uri ;;
  }
}

view: findings__finding__ip_rules__denied__ip_rules {

  dimension: port_ranges {
    hidden: yes
    sql: ${TABLE}.port_ranges ;;
  }
  dimension: protocol {
    type: string
    sql: ${TABLE}.protocol ;;
  }
}

view: findings__finding__backup_disaster_recovery__policies {

  dimension: findings__finding__backup_disaster_recovery__policies {
    type: string
    sql: findings__finding__backup_disaster_recovery__policies ;;
  }
}

view: findings__finding__mitre_attack__additional_techniques {

  dimension: findings__finding__mitre_attack__additional_techniques {
    type: string
    sql: findings__finding__mitre_attack__additional_techniques ;;
  }
}

view: findings__finding__ip_rules__allowed__ip_rules {

  dimension: port_ranges {
    hidden: yes
    sql: ${TABLE}.port_ranges ;;
  }
  dimension: protocol {
    type: string
    sql: ${TABLE}.protocol ;;
  }
}

view: findings__finding__backup_disaster_recovery__applications {

  dimension: findings__finding__backup_disaster_recovery__applications {
    type: string
    sql: findings__finding__backup_disaster_recovery__applications ;;
  }
}

view: findings__finding__kubernetes__pods__containers__labels {

  dimension: name {
    type: string
    sql: ${TABLE}.name ;;
  }
  dimension: value {
    type: string
    sql: ${TABLE}.value ;;
  }
}

view: findings__finding__backup_disaster_recovery__policy_options {

  dimension: findings__finding__backup_disaster_recovery__policy_options {
    type: string
    sql: findings__finding__backup_disaster_recovery__policy_options ;;
  }
}

view: findings__finding__contacts__contact_details__contacts {

  dimension: email {
    type: string
    sql: ${TABLE}.email ;;
  }
}

view: findings__finding__ip_rules__denied__ip_rules__port_ranges {

  dimension: max {
    type: number
    sql: ${TABLE}.max ;;
  }
  dimension: min {
    type: number
    sql: ${TABLE}.min ;;
  }
}

view: findings__finding__kubernetes__objects__containers__labels {

  dimension: name {
    type: string
    sql: ${TABLE}.name ;;
  }
  dimension: value {
    type: string
    sql: ${TABLE}.value ;;
  }
}

view: findings__finding__ip_rules__allowed__ip_rules__port_ranges {

  dimension: max {
    type: number
    sql: ${TABLE}.max ;;
  }
  dimension: min {
    type: number
    sql: ${TABLE}.min ;;
  }
}

view: findings__finding__indicator__signatures {

  dimension: memory_hash_signature__binary_family {
    type: string
    sql: ${TABLE}.memory_hash_signature.binary_family ;;
    group_label: "Memory Hash Signature"
    group_item_label: "Binary Family"
  }
  dimension: memory_hash_signature__detections {
    hidden: yes
    sql: ${TABLE}.memory_hash_signature.detections ;;
    group_label: "Memory Hash Signature"
    group_item_label: "Detections"
  }
  dimension: yara_rule_signature__yara_rule {
    type: string
    sql: ${TABLE}.yara_rule_signature.yara_rule ;;
    group_label: "Yara Rule Signature"
    group_item_label: "Yara Rule"
  }
}

view: findings__finding__access__service_account_delegation_info {

  dimension: principal_email {
    type: string
    sql: ${TABLE}.principal_email ;;
  }
  dimension: principal_subject {
    type: string
    sql: ${TABLE}.principal_subject ;;
  }
}

view: findings__finding__indicator__signatures__memory_hash_signature__detections {

  dimension: binary {
    type: string
    sql: ${TABLE}.binary ;;
  }
  dimension: percent_pages_matched {
    type: number
    sql: ${TABLE}.percent_pages_matched ;;
  }
}
