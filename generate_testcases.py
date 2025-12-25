import json
from pathlib import Path

def generate_test_cases():
    test_cases = {
        "metadata": {
            "total_cases": 55,
            "dvwa_cases": 16,
            "sqli_labs_cases": 19,
            "false_positive_cases": 15,
            "risk_distribution": {
                "L1": 11,
                "L2": 16,
                "L3": 14,
                "L4": 14
            }
        },
        "test_cases": []
    }
    
    #DVWA Low
    tc001 = {
        "id": "TC001",
        "name": "DVWA SQL Injection (Low) - Electronic Prescription System",
        "platform": "DVWA",
        "level": "SQL Injection",
        "security_level": "Low",
        "ground_truth": True,
        "vulnerability_type": "Error-based",
        "url": "http://192.168.10.20/DVWA/vulnerabilities/sqli/?id=1&Submit=Submit#",
        "medical_context": {
            "module": "Electronic Prescription System",
            "risk_level": "L1",
            "parameter": "prescription_id",
            "data_sensitivity": "CRITICAL"
        },
        "sqlmap_result": {
            "status_code": 200,
            "delay_time": 6.4,
            "error_keywords": ["GTID_SUBSET", "MySQL", "syntax error", "near", "unexpected", 
                "Warning", "mysql_fetch", "SELECT", "FROM", "database"],
            "vulnerability_type": "Error-based",
            "successful_payloads": 19,
            "total_payloads": 20,
            "dbms_detected": True,
            "data_dumped": True,
            "parameter_name": "prescription_id"
        },
        "zap_result": {
            "status_code": 200,
            "response_time": 410,
            "content_length_change": 0.95,
            "alert_level": "High",
            "triggered_rules": 9,
            "total_rules": 10,
            "dbms_detected": True,
            "parameter_name": "prescription_id"
        },
    }
    test_cases["test_cases"].append(tc001)
    
    tc002 = {
        "id": "TC002",
        "name": "DVWA SQL Injection (Low) -Prescription Drug Information",
        "platform": "DVWA",
        "level": "SQL Injection",
        "security_level": "Low",
        "ground_truth": True,
        "vulnerability_type": "UNION Query",
        "url": "http://192.168.10.20/DVWA/vulnerabilities/sqli/?id=1&Submit=Submit#",
        "medical_context": {
            "module": "Electronic Prescription System",
            "risk_level": "L1",
            "parameter": "prescription_drug_id",
            "data_sensitivity": "CRITICAL"
        },
        "sqlmap_result": {
            "status_code": 200,
            "delay_time": 6.8,
            "error_keywords": ["GTID_SUBSET", "MySQL", "syntax error", "UNION", "SELECT", 
                "column", "mismatch", "number", "operand", "Warning", 
                "mysql_num_rows", "query"],
            "vulnerability_type": "UNION query",
            "successful_payloads": 20,
            "total_payloads": 20,
            "dbms_detected": True,
            "data_dumped": True,
            "parameter_name": "prescription_drug_id"
        },
        "zap_result": {
            "status_code": 200,
            "response_time": 470,
            "content_length_change": 0.95,
            "alert_level": "High",
            "triggered_rules": 9,
            "total_rules": 10,
            "dbms_detected": True,
            "parameter_name": "prescription_drug_id"
        }
    }
    test_cases["test_cases"].append(tc002)
    
    tc009 = {
        "id": "TC009",
        "name": "DVWA SQL Injection (Low) - Lab report System",
        "platform": "DVWA",
        "level": "SQL Injection",
        "security_level": "Low",
        "ground_truth": True,
        "vulnerability_type": "Error-based",
        "url": "http://192.168.10.20/DVWA/vulnerabilities/sqli/?id=1&Submit=Submit#",
        "medical_context": {
            "module": "Electronic Prescription System",
            "risk_level": "L3",
            "parameter": "lab_report_id",
            "data_sensitivity": "MEDIUM"
        },
        "sqlmap_result": {
            "status_code": 200,
            "delay_time": 5.0,
            "error_keywords": ["MySQL", "syntax error", "SELECT", "Warning", 
                "mysql_fetch", "database", "column", "row"],
            "vulnerability_type": "Error-based",
            "successful_payloads": 18,
            "total_payloads": 20,
            "dbms_detected": True,
            "data_dumped": True,
            "parameter_name": "lab_report_id"
        },
        "zap_result": {
            "status_code": 200,
            "response_time": 380,
            "content_length_change": 0.95,
            "alert_level": "High",
            "triggered_rules": 8,
            "total_rules": 10,
            "dbms_detected": True,
            "parameter_name": "lab_report_id"
        }
    }
    test_cases["test_cases"].append(tc009)
    
    tc013 = {
        "id": "TC013",
        "name": "DVWA SQL Injection (Low) - Appointment Scheduling",
        "platform": "DVWA",
        "level": "SQL Injection",
        "security_level": "Low",
        "ground_truth": True,
        "vulnerability_type": "Error-based",
        "url": "http://192.168.10.20/DVWA/vulnerabilities/sqli/?id=1&Submit=Submit#",
        "medical_context": {
            "module": "Appointment Scheduling",
            "risk_level": "L4",
            "parameter": "appointment_id",
            "data_sensitivity": "LOW"
        },
        "sqlmap_result": {
            "status_code": 200,
            "delay_time": 3.4,
            "error_keywords": [],
            "vulnerability_type": "",
            "successful_payloads": 7,
            "total_payloads": 20,
            "dbms_detected": False,
            "data_dumped": False,
            "parameter_name": "appointment_id"
        },
        "zap_result": {
            "status_code": 200,
            "response_time": 320,
            "content_length_change": 0.85,
            "alert_level": "High",
            "triggered_rules": 8,
            "total_rules": 10,
            "dbms_detected": True,
            "parameter_name": "appointment_id"
        }
    }
    test_cases["test_cases"].append(tc013)
    
    #DVWA Medium
    tc003 = {
        "id": "TC003",
        "name": "DVWA SQL Injection (Medium) - Surgical Record System",
        "platform": "DVWA",
        "level": "SQL Injection",
        "security_level": "Medium",
        "ground_truth": True,
        "vulnerability_type": "Error-based",
        "url": "http://192.168.10.20/DVWA/vulnerabilities/sqli/#",
        "medical_context": {
            "module": "Surgical Record System",
            "risk_level": "L1",
            "parameter": "surgery_record_id",
            "data_sensitivity": "CRITICAL"
        },
        "sqlmap_result": {
            "status_code": 200,
            "delay_time": 8.3,
            "error_keywords": ["syntax error"],
            "vulnerability_type": "Error-based",
            "successful_payloads": 12,
            "total_payloads": 20,
            "dbms_detected": True,
            "data_dumped": False,
            "parameter_name": "surgery_record_id"
        },
        "zap_result": {
            "status_code": 200,
            "response_time": 680,
            "content_length_change": 0.50,
            "alert_level": "Medium",
            "triggered_rules": 6,
            "total_rules": 10,
            "dbms_detected": True,
            "parameter_name": "surgery_record_id"
        }
    }
    test_cases["test_cases"].append(tc003)
    
    tc010 = {
        "id": "TC010",
        "name": "DVWA SQL Injection (Medium) - Insurance Settlement",
        "platform": "DVWA",
        "level": "SQL Injection",
        "security_level": "Medium",
        "ground_truth": True,
        "vulnerability_type": "Error-based",
        "url": "http://192.168.10.20/DVWA/vulnerabilities/sqli/#",
        "medical_context": {
            "module": "Insurance Settlement",
            "risk_level": "L3",
            "parameter": "insurance_claim_id",
            "data_sensitivity": "MEDIUM"
        },
        "sqlmap_result": {
            "status_code": 200,
            "delay_time": 7.1,
            "error_keywords": ["query"],
            "vulnerability_type": "Error-based",
            "successful_payloads": 14,
            "total_payloads": 20,
            "dbms_detected": True,
            "data_dumped": False,
            "parameter_name": "insurance_claim_id"
        },
        "zap_result": {
            "status_code": 200,
            "response_time": 309,
            "content_length_change": 0.52,
            "alert_level": "Medium",
            "triggered_rules": 6,
            "total_rules": 10,
            "dbms_detected": True,
            "parameter_name": "insurance_claim_id"
        }
    }
    test_cases["test_cases"].append(tc010)
    
    tc014 = {
        "id": "TC014",
        "name": "DVWA SQL Injection (Medium) - Room Assignment",
        "platform": "DVWA",
        "level": "SQL Injection",
        "security_level": "Medium",
        "ground_truth": True,
        "vulnerability_type": "Error-based",
        "url": "http://192.168.10.20/DVWA/vulnerabilities/sqli/#",
        "medical_context": {
            "module": "Room Assignment",
            "risk_level": "L4",
            "parameter": "room_schedule_id",
            "data_sensitivity": "LOW"
        },
        "sqlmap_result": {
            "status_code": 200,
            "delay_time": 6.5,
            "error_keywords": [],
            "vulnerability_type": "",
            "successful_payloads": 7,
            "total_payloads": 20,
            "dbms_detected": False,
            "data_dumped": False,
            "parameter_name": "room_schedule_id"
        },
        "zap_result": {
            "status_code": 200,
            "response_time": 420,
            "content_length_change": 0.82,
            "alert_level": "High",
            "triggered_rules": 8,
            "total_rules": 10,
            "dbms_detected": True,
            "parameter_name": "room_schedule_id"
        }
    }
    test_cases["test_cases"].append(tc014)
    
    #DVWA High
    tc004 = {
        "id": "TC004",
        "name": "DVWA SQL Injection (High) - Electronic Prescription System",
        "platform": "DVWA",
        "level": "SQL Injection",
        "security_level": "High",
        "ground_truth": False,
        "vulnerability_type": "",
        "url": "http://192.168.10.20/DVWA/vulnerabilities/sqli/session-input.php#",
        "medical_context": {
            "module": "Electronic Prescription System",
            "risk_level": "L1",
            "parameter": "prescription_id",
            "data_sensitivity": "CRITICAL"
        },
        "sqlmap_result": {
            "status_code": 200,
            "delay_time": 0.5,
            "error_keywords": [],
            "vulnerability_type": "",
            "successful_payloads": 0,
            "total_payloads": 20,
            "dbms_detected": False,
            "data_dumped": False,
            "parameter_name": "prescription_id"
        },
        "zap_result": {
            "status_code": 200,
            "response_time": 151,
            "content_length_change": 0.01,
            "alert_level": "Low",
            "triggered_rules": 0,
            "total_rules": 10,
            "dbms_detected": False,
            "parameter_name": "prescription_id"
        }
    }
    test_cases["test_cases"].append(tc004)
    
    tc016 = {
        "id": "TC016",
        "name": "DVWA SQL Injection (High) - Appointment Scheduling",
        "platform": "DVWA",
        "level": "SQL Injection",
        "security_level": "High",
        "ground_truth": False,
        "vulnerability_type": "",
        "url": "http://192.168.10.20/DVWA/vulnerabilities/sqli/session-input.php#",
        "medical_context": {
            "module": "Appointment Scheduling",
            "risk_level": "L4",
            "parameter": "appointment_id",
            "data_sensitivity": "LOW"
        },
        "sqlmap_result": {
            "status_code": 200,
            "delay_time": 0.5,
            "error_keywords": [],
            "vulnerability_type": "",
            "successful_payloads": 0,
            "total_payloads": 20,
            "dbms_detected": False,
            "data_dumped": False,
            "parameter_name": "appointment_id"
        },
        "zap_result": {
            "status_code": 200,
            "response_time": 151,
            "content_length_change": 0.01,
            "alert_level": "Low",
            "triggered_rules": 0,
            "total_rules": 10,
            "dbms_detected": False,
            "parameter_name": "appointment_id"
        }
    }
    test_cases["test_cases"].append(tc016)
    
    #DVWA Low - Boolean Blind
    tc005 = {
        "id": "TC005",
        "name": "DVWA Boolean Blind - Patient Information Query",
        "platform": "DVWA",
        "level": "SQL Injection Blind",
        "security_level": "Low",
        "ground_truth": True,
        "vulnerability_type": "Boolean-based blind",
        "url": "http://192.168.10.20/DVWA/vulnerabilities/sqli_blind/?id=1&Submit=Submit#",
        "medical_context": {
            "module": "Patient Information Query",
            "risk_level": "L2",
            "parameter": "patient_id",
            "data_sensitivity": "HIGH"
        },
        "sqlmap_result": {
            "status_code": 200,
            "delay_time": 5.0,
            "error_keywords": ["GTID_SUBSET", "MySQL", "syntax error", "SELECT", "WHERE",
            "Boolean", "condition", "Warning", "database"],
            "vulnerability_type": "Boolean-based blind",
            "successful_payloads": 18,
            "total_payloads": 20,
            "dbms_detected": True,
            "data_dumped": True,
            "parameter_name": "patient_id"
        },
        "zap_result": {
            "status_code": 200,
            "response_time": 319,
            "content_length_change": 0.12,
            "alert_level": "Low",
            "triggered_rules": 2,
            "total_rules": 10,
            "dbms_detected": False,
            "parameter_name": "patient_id"
        }
    }
    test_cases["test_cases"].append(tc005)
    
    tc006 = {
        "id": "TC006",
        "name": "DVWA Time-based Blind - Medical History",
        "platform": "DVWA",
        "level": "SQL Injection Blind",
        "security_level": "Low",
        "ground_truth": True,
        "vulnerability_type": "Time-based",
        "url": "http://192.168.10.20/DVWA/vulnerabilities/sqli_blind/?id=1&Submit=Submit#",
        "medical_context": {
            "module": "Patient Medical History",
            "risk_level": "L2",
            "parameter": "patient_record_id",
            "data_sensitivity": "HIGH"
        },
        "sqlmap_result": {
            "status_code": 200,
            "delay_time": 14.5,
            "error_keywords": ["GTID_SUBSET", "MySQL", "syntax error", "SLEEP", "BENCHMARK",
            "time", "delay", "SELECT", "Warning", "database"],
            "vulnerability_type": "Time-based",
            "successful_payloads": 18,
            "total_payloads": 20,
            "dbms_detected": True,
            "data_dumped": True,
            "parameter_name": "patient_record_id"
        },
        "zap_result": {
            "status_code": 200,
            "response_time": 142,
            "content_length_change": 0.21,
            "alert_level": "Low",
            "triggered_rules": 2,
            "total_rules": 10,
            "dbms_detected": False,
            "parameter_name": "patient_record_id"
        }
    }
    test_cases["test_cases"].append(tc006)
    
    tc011 = {
        "id": "TC011",
        "name": "DVWA Boolean Blind - Medical Imaging System",
        "platform": "DVWA",
        "level": "SQL Injection Blind",
        "security_level": "Low",
        "ground_truth": True,
        "vulnerability_type": "Boolean-based blind",
        "url": "http://192.168.10.20/DVWA/vulnerabilities/sqli_blind/?id=1&Submit=Submit#",
        "medical_context": {
            "module": "Medical Imaging System",
            "risk_level": "L3",
            "parameter": "imaging_study_id",
            "data_sensitivity": "MEDIUM"
        },
        "sqlmap_result": {
            "status_code": 200,
            "delay_time": 3.5,
            "error_keywords": ["GTID_SUBSET", "MySQL", "syntax error", "Boolean", "SELECT", "Warning", "database"],
            "vulnerability_type": "Boolean-based blind",
            "successful_payloads": 18,
            "total_payloads": 20,
            "dbms_detected": True,
            "data_dumped": False,
            "parameter_name": "imaging_study_id"
        },
        "zap_result": {
            "status_code": 200,
            "response_time": 205,
            "content_length_change": 0.12,
            "alert_level": "Low",
            "triggered_rules": 3,
            "total_rules": 10,
            "dbms_detected": False,
            "parameter_name": "imaging_study_id"
        }
    }
    test_cases["test_cases"].append(tc011)
    
    tc015 = {
        "id": "TC015",
        "name": "DVWA Boolean Blind - Department Directory",
        "platform": "DVWA",
        "level": "SQL Injection Blind",
        "security_level": "Low",
        "ground_truth": True,
        "vulnerability_type": "Boolean-based blind",
        "url": "http://192.168.10.20/DVWA/vulnerabilities/sqli_blind/?id=1&Submit=Submit#",
        "medical_context": {
            "module": "Department Directory",
            "risk_level": "L4",
            "parameter": "department_id",
            "data_sensitivity": "LOW"
        },
        "sqlmap_result": {
            "status_code": 200,
            "delay_time": 3.8,
            "error_keywords": ["GTID_SUBSET", "MySQL", "syntax error", "Boolean", "SELECT", "Warning"],
            "vulnerability_type": "Boolean-based blind",
            "successful_payloads": 16,
            "total_payloads": 20,
            "dbms_detected": True,
            "data_dumped": False,
            "parameter_name": "department_id"
        },
        "zap_result": {
            "status_code": 200,
            "response_time": 275,
            "content_length_change": 0.12,
            "alert_level": "Low",
            "triggered_rules": 2,
            "total_rules": 10,
            "dbms_detected": False,
            "parameter_name": "department_id"
        }
    }
    test_cases["test_cases"].append(tc015)
    
    #DVWA Medium - Boolean Blind
    tc007 = {
        "id": "TC007",
        "name": "DVWA Boolean Blind - Authentication System",
        "platform": "DVWA",
        "level": "SQL Injection Blind",
        "security_level": "Medium",
        "ground_truth": True,
        "vulnerability_type": "Boolean-based blind",
        "url": "http://192.168.10.20/DVWA/vulnerabilities/sqli_blind/#",
        "medical_context": {
            "module": "Authentication System",
            "risk_level": "L2",
            "parameter": "user_auth_id",
            "data_sensitivity": "HIGH"
        },
        "sqlmap_result": {
            "status_code": 200,
            "delay_time": 5.8,
            "error_keywords": ["SELECT"],
            "vulnerability_type": "Boolean-based blind",
            "successful_payloads": 14,
            "total_payloads": 20,
            "dbms_detected": True,
            "data_dumped": False,
            "parameter_name": "user_auth_id"
        },
        "zap_result": {
            "status_code": 200,
            "response_time": 280,
            "content_length_change": 0.52,
            "alert_level": "Medium",
            "triggered_rules": 6,
            "total_rules": 10,
            "dbms_detected": True,
            "parameter_name": "user_auth_id"
        }
    }
    test_cases["test_cases"].append(tc007)
    
    tc008 = {
        "id": "TC008",
        "name": "DVWA Boolean Blind - Doctor Login System",
        "platform": "DVWA",
        "level": "SQL Injection Blind",
        "security_level": "Medium",
        "ground_truth": True,
        "vulnerability_type": "Time-based",
        "url": "http://192.168.10.20/DVWA/vulnerabilities/sqli_blind/#",
        "medical_context": {
            "module": "Doctor Login System",
            "risk_level": "L2",
            "parameter": "doctor_id",
            "data_sensitivity": "HIGH"
        },
        "sqlmap_result": {
            "status_code": 200,
            "delay_time": 14.2,
            "error_keywords": ["MySQL", "SLEEP", "BENCHMARK", "time", "delay"],
            "vulnerability_type": "Time-based",
            "successful_payloads": 16,
            "total_payloads": 20,
            "dbms_detected": True,
            "data_dumped": True,
            "parameter_name": "doctor_id"
        },
        "zap_result": {
            "status_code": 200,
            "response_time": 210,
            "content_length_change": 0.15,
            "alert_level": "Low",
            "triggered_rules": 2,
            "total_rules": 10,
            "dbms_detected": False,
            "parameter_name": "doctor_id"
        }
    }
    test_cases["test_cases"].append(tc008)
    
    #DVWA High - Boolean Blind
    tc012 = {
        "id": "TC012",
        "name": "DVWA Boolean Blind - Insurance Settlement",
        "platform": "DVWA",
        "level": "SQL Injection",
        "security_level": "High",
        "ground_truth": False,
        "vulnerability_type": "",
        "url": "http://192.168.10.20/DVWA/vulnerabilities/sqli_blind/cookie-input.php#",
        "medical_context": {
            "module": "Insurance Settlement",
            "risk_level": "L3",
            "parameter": "claim_id",
            "data_sensitivity": "MEDIUM"
        },
        "sqlmap_result": {
            "status_code": 200,
            "delay_time": 0.5,
            "error_keywords": [],
            "vulnerability_type": "",
            "successful_payloads": 0,
            "total_payloads": 20,
            "dbms_detected": False,
            "data_dumped": False,
            "parameter_name": "claim_id"
        },
        "zap_result": {
            "status_code": 200,
            "response_time": 13,
            "content_length_change": 0.15,
            "alert_level": "Low",
            "triggered_rules": 2,
            "total_rules": 10,
            "dbms_detected": False,
            "parameter_name": "claim_id"
        }
    }
    test_cases["test_cases"].append(tc012)
    
    #sqli-labs 
    tc017 = {
        "id": "TC017",
        "name": "Sqli-labs SQL Injection - HIV Status Records",
        "platform": "sqli-labs",
        "level": "Less-1",
        "ground_truth": True,
        "vulnerability_type": "Error-based (Single Quote)",
        "url": "http://192.168.10.20/sqli-labs/Less-1/?id=1'",
        "medical_context": {
            "module": "HIV Status Records",
            "risk_level": "L1",
            "parameter": "hiv_test_id",
            "data_sensitivity": "CRITICAL"
        },
        "sqlmap_result": {
            "status_code": 200,
            "delay_time": 6.5,
            "error_keywords": ["GTID_SUBSET", "MySQL", "syntax error", "SELECT", "FROM", 
                            "WHERE", "LIMIT", "database", "query", "ERROR"],
            "vulnerability_type": "Error-based",
            "successful_payloads": 20,
            "total_payloads": 20,
            "dbms_detected": True,
            "data_dumped": True,
            "parameter_name": "hiv_test_id"
        },
        "zap_result": {
            "status_code": 200,
            "response_time": 480,
            "content_length_change": 0.88,
            "alert_level": "High",
            "triggered_rules": 9,
            "total_rules": 10,
            "dbms_detected": True,
            "parameter_name": "hiv_test_id"
        },
    }
    test_cases["test_cases"].append(tc017)
    
    tc018 = {
        "id": "TC018",
        "name": "Sqli-labs SQL Injection - Genetic Test System",
        "platform": "sqli-labs",
        "level": "Less-2",
        "ground_truth": True,
        "vulnerability_type": "Error-based (Numeric)",
        "url": "http://192.168.10.20/sqli-labs/Less-2/?id=1",
        "medical_context": {
            "module": "Genetic Test System",
            "risk_level": "L1",
            "parameter": "genetic_data_id",
            "data_sensitivity": "CRITICAL"
        },
        "sqlmap_result": {
            "status_code": 200,
            "delay_time": 6.8,
            "error_keywords": ["GTID_SUBSET", "MySQL", "syntax error", "SELECT", "FROM", 
                            "numeric", "integer", "database", "query", "ERROR"],
            "vulnerability_type": "Error-based",
            "successful_payloads": 20,
            "total_payloads": 20,
            "dbms_detected": True,
            "data_dumped": True,
            "parameter_name": "genetic_data_id"
        },
        "zap_result": {
            "status_code": 200,
            "response_time": 520,
            "content_length_change": 0.90,
            "alert_level": "High",
            "triggered_rules": 9,
            "total_rules": 10,
            "dbms_detected": True,
            "parameter_name": "genetic_data_id"
        },
    }
    test_cases["test_cases"].append(tc018)
    
    tc019 = {
        "id": "TC019",
        "name": "Sqli-labs SQL Injection - Mental Health Records",
        "platform": "sqli-labs",
        "level": "Less-3",
        "ground_truth": True,
        "vulnerability_type": "Error-based (Single Quote with Parenthesis)",
        "url": "http://192.168.10.20/sqli-labs/Less-3/?id=1",
        "medical_context": {
            "module": "Mental Health Records",
            "risk_level": "L1",
            "parameter": "psychiatric_record_id",
            "data_sensitivity": "CRITICAL"
        },
        "sqlmap_result": {
            "status_code": 200,
            "delay_time": 7.2,
            "error_keywords": ["GTID_SUBSET", "MySQL", "syntax error", "SELECT", "parenthesis", 
                            "quote", "database", "query", "ERROR", "Warning"],
            "vulnerability_type": "Error-based",
            "successful_payloads": 19,
            "total_payloads": 20,
            "dbms_detected": True,
            "data_dumped": True,
            "parameter_name": "psychiatric_record_id"
        },
        "zap_result": {
            "status_code": 200,
            "response_time": 420,
            "content_length_change": 0.55,
            "alert_level": "High",
            "triggered_rules": 8,
            "total_rules": 10,
            "dbms_detected": True,
            "parameter_name": "psychiatric_record_id"
        },
    }
    test_cases["test_cases"].append(tc019)
    
    tc020 = {
        "id": "TC020",
        "name": "Sqli-labs SQL Injection - Oncology Treatment Plan",
        "platform": "sqli-labs",
        "level": "Less-4",
        "ground_truth": True,
        "vulnerability_type": "Error-based (Double Quote)",
        "url": "http://192.168.10.20/sqli-labs/Less-4/?id=1",
        "medical_context": {
            "module": "Oncology Treatment Plan",
            "risk_level": "L1",
            "parameter": "cancer_treatment_id",
            "data_sensitivity": "CRITICAL"
        },
        "sqlmap_result": {
            "status_code": 200,
            "delay_time": 6.5,
            "error_keywords": ["GTID_SUBSET", "MySQL", "syntax error", "SELECT", "double", 
                            "quote", "database", "query", "ERROR", "Warning"],
            "vulnerability_type": "Error-based",
            "successful_payloads": 19,
            "total_payloads": 20,
            "dbms_detected": True,
            "data_dumped": True,
            "parameter_name": "cancer_treatment_id"
        },
        "zap_result": {
            "status_code": 200,
            "response_time": 450,
            "content_length_change": 0.75,
            "alert_level": "High",
            "triggered_rules": 7,
            "total_rules": 10,
            "dbms_detected": True,
            "parameter_name": "cancer_treatment_id"
        },
    }
    test_cases["test_cases"].append(tc020)
    
    tc021 = {
        "id": "TC021",
        "name": "Sqli-labs SQL Injection - Patient Demographics",
        "platform": "sqli-labs",
        "level": "Less-5",
        "ground_truth": True,
        "vulnerability_type": "Boolean-based Blind",
        "url": "http://192.168.10.20/sqli-labs/Less-5/?id=1",
        "medical_context": {
            "module": "Patient Demographics",
            "risk_level": "L2",
            "parameter": "patient_demographic_id",
            "data_sensitivity": "HIGH"
        },
        "sqlmap_result": {
            "status_code": 200,
            "delay_time": 5.2,
            "error_keywords": ["GTID_SUBSET", "MySQL", "syntax error", "SELECT", "WHERE", 
                            "Boolean", "condition", "AND", "OR"],
            "vulnerability_type": "Boolean-based Blind",
            "successful_payloads": 18,
            "total_payloads": 20,
            "dbms_detected": True,
            "data_dumped": False,
            "parameter_name": "patient_demographic_id"
        },
        "zap_result": {
            "status_code": 200,
            "response_time": 345,
            "content_length_change": 0.12,
            "alert_level": "Low",
            "triggered_rules": 2,
            "total_rules": 10,
            "dbms_detected": False,
            "parameter_name": "patient_demographic_id"
        },
    }
    test_cases["test_cases"].append(tc021)
    
    tc022 = {
        "id": "TC022",
        "name": "Sqli-labs SQL Injection - Diagnosis Records",
        "platform": "sqli-labs",
        "level": "Less-6",
        "ground_truth": True,
        "vulnerability_type": "Boolean-based Blind (Double Quote)",
        "url": "http://192.168.10.20/sqli-labs/Less-6/?id=1",
        "medical_context": {
            "module": "Diagnosis Records",
            "risk_level": "L2",
            "parameter": "diagnosis_id",
            "data_sensitivity": "HIGH"
        },
        "sqlmap_result": {
            "status_code": 200,
            "delay_time": 4.5,
            "error_keywords": [],
            "vulnerability_type": "",
            "successful_payloads": 8,
            "total_payloads": 20,
            "dbms_detected": False,
            "data_dumped": False,
            "parameter_name": "diagnosis_id"
        },
        "zap_result": {
            "status_code": 200,
            "response_time": 269,
            "content_length_change": 0.88,
            "alert_level": "High",
            "triggered_rules": 9,
            "total_rules": 10,
            "dbms_detected": True,
            "parameter_name": "diagnosis_id"
        },
    }
    test_cases["test_cases"].append(tc022)
    
    tc023 = {
        "id": "TC023",
        "name": "Sqli-labs SQL Injection - Electronic Health Records",
        "platform": "sqli-labs",
        "level": "Less-7",
        "ground_truth": True,
        "vulnerability_type": "Outfile Injection",
        "url": "http://192.168.10.20/sqli-labs/Less-7/?id=1",
        "medical_context": {
            "module": "Electronic Health Records",
            "risk_level": "L2",
            "parameter": "ehr_record_id",
            "data_sensitivity": "HIGH"
        },
        "sqlmap_result": {
            "status_code": 200,
            "delay_time": 5.0,
            "error_keywords": [],
            "vulnerability_type": "",
            "successful_payloads": 6,
            "total_payloads": 20,
            "dbms_detected": False,
            "data_dumped": False,
            "parameter_name": "ehr_record_id"
        },
        "zap_result": {
            "status_code": 200,
            "response_time": 390,
            "content_length_change": 0.75,
            "alert_level": "High",
            "triggered_rules": 9,
            "total_rules": 10,
            "dbms_detected": True,
            "parameter_name": "ehr_record_id"
        },
    }
    test_cases["test_cases"].append(tc023)
    
    tc024 = {
        "id": "TC024",
        "name": "Sqli-labs SQL Injection - Patient Allergy Records",
        "platform": "sqli-labs",
        "level": "Less-8",
        "ground_truth": True,
        "vulnerability_type": "Boolean-based Blind",
        "url": "http://192.168.10.20/sqli-labs/Less-8/?id=1",
        "medical_context": {
            "module": "Patient Allergy Records",
            "risk_level": "L2",
            "parameter": "allergy_record_id",
            "data_sensitivity": "HIGH"
        },
        "sqlmap_result": {
            "status_code": 200,
            "delay_time": 4.1,
            "error_keywords": ["GTID_SUBSET", "MySQL", "syntax error", "SELECT", "WHERE", 
                            "Boolean", "condition", "blind", "query"],
            "vulnerability_type": "Boolean-based Blind",
            "successful_payloads": 18,
            "total_payloads": 20,
            "dbms_detected": True,
            "data_dumped": False,
            "parameter_name": "allergy_record_id"
        },
        "zap_result": {
            "status_code": 200,
            "response_time": 291,
            "content_length_change": 0.15,
            "alert_level": "Low",
            "triggered_rules": 2,
            "total_rules": 10,
            "dbms_detected": False,
            "parameter_name": "allergy_record_id"
        },
    }
    test_cases["test_cases"].append(tc024)
    
    tc025 = {
        "id": "TC025",
        "name": "Sqli-labs SQL Injection - Pathology Reports",
        "platform": "sqli-labs",
        "level": "Less-9",
        "ground_truth": True,
        "vulnerability_type": "Time-based Blind",
        "url": "http://192.168.10.20/sqli-labs/Less-9/?id=1",
        "medical_context": {
            "module": "Pathology Reports",
            "risk_level": "L2",
            "parameter": "pathology_report_id",
            "data_sensitivity": "HIGH"
        },
        "sqlmap_result": {
            "status_code": 200,
            "delay_time": 13.5,
            "error_keywords": ["GTID_SUBSET", "MySQL", "syntax error", "SLEEP", "BENCHMARK", 
                            "time", "delay", "seconds", "wait"],
            "vulnerability_type": "Time-based Blind",
            "successful_payloads": 18,
            "total_payloads": 20,
            "dbms_detected": True,
            "data_dumped": False,
            "parameter_name": "pathology_report_id"
        },
        "zap_result": {
            "status_code": 200,
            "response_time": 163,
            "content_length_change": 0.14,
            "alert_level": "Low",
            "triggered_rules": 2,
            "total_rules": 10,
            "dbms_detected": False,
            "parameter_name": "pathology_report_id"
        },
    }
    test_cases["test_cases"].append(tc025)
    
    tc026 = {
        "id": "TC026",
        "name": "Sqli-labs SQL Injection - Treatment History",
        "platform": "sqli-labs",
        "level": "Less-10",
        "ground_truth": True,
        "vulnerability_type": "Time-based Blind (Double Quote)",
        "url": "http://192.168.10.20/sqli-labs/Less-10/?id=1",
        "medical_context": {
            "module": "Treatment History",
            "risk_level": "L2",
            "parameter": "treatment_history_id",
            "data_sensitivity": "HIGH"
        },
        "sqlmap_result": {
            "status_code": 200,
            "delay_time": 15.8,
            "error_keywords": ["GTID_SUBSET", "MySQL", "syntax error", "SLEEP", "BENCHMARK", 
                            "time", "delay", "double", "quote"],
            "vulnerability_type": "Time-based Blind (Double Quote)",
            "successful_payloads": 18,
            "total_payloads": 20,
            "dbms_detected": True,
            "data_dumped": False,
            "parameter_name": "treatment_history_id"
        },
        "zap_result": {
            "status_code": 200,
            "response_time": 277,
            "content_length_change": 0.11,
            "alert_level": "Low",
            "triggered_rules": 2,
            "total_rules": 10,
            "dbms_detected": False,
            "parameter_name": "treatment_history_id"
        },
    }
    test_cases["test_cases"].append(tc026)
    
    tc027 = {
        "id": "TC027",
        "name": "Sqli-labs SQL Injection - Admin Login Panel",
        "platform": "sqli-labs",
        "level": "Less-11",
        "ground_truth": True,
        "vulnerability_type": "Error-based (POST)",
        "url": "http://192.168.10.20/sqli-labs/Less-11/",
        "medical_context": {
            "module": "Admin Login Panel",
            "risk_level": "L2",
            "parameter": "admin_username",
            "data_sensitivity": "HIGH"
        },
        "sqlmap_result": {
            "status_code": 200,
            "delay_time": 5.5,
            "error_keywords": ["POST", "authentication", "login", "username", "database", "ERROR"],
            "vulnerability_type": "Error-based (POST)",
            "successful_payloads": 8,
            "total_payloads": 20,
            "dbms_detected": True,
            "data_dumped": False,
            "parameter_name": "admin_username"
        },
        "zap_result": {
            "status_code": 200,
            "response_time": 440,
            "content_length_change": 0.65,
            "alert_level": "High",
            "triggered_rules": 9,
            "total_rules": 10,
            "dbms_detected": True,
            "parameter_name": "admin_username"
        },
    }
    test_cases["test_cases"].append(tc027)
    
    tc028 = {
        "id": "TC028",
        "name": "Sqli-labs SQL Injection - Pharmacy System Login",
        "platform": "sqli-labs",
        "level": "Less-12",
        "ground_truth": True,
        "vulnerability_type": "Error-based (POST Double Quote)",
        "url": "http://192.168.10.20/sqli-labs/Less-12/",
        "medical_context": {
            "module": "Pharmacy System Login",
            "risk_level": "L2",
            "parameter": "pharmacist_id",
            "data_sensitivity": "HIGH"
        },
        "sqlmap_result": {
            "status_code": 200,
            "delay_time": 5.8,
            "error_keywords": ["quote", "login", "database", "ERROR"],
            "vulnerability_type": "Error-based (POST Double Quote)",
            "successful_payloads": 8,
            "total_payloads": 20,
            "dbms_detected": True,
            "data_dumped": False,
            "parameter_name": "pharmacist_id"
        },
        "zap_result": {
            "status_code": 200,
            "response_time": 310,
            "content_length_change": 0.72,
            "alert_level": "High",
            "triggered_rules": 9,
            "total_rules": 10,
            "dbms_detected": True,
            "parameter_name": "pharmacist_id"
        },
    }
    test_cases["test_cases"].append(tc028)
    
    tc029 = {
        "id": "TC029",
        "name": "Sqli-labs SQL Injection - Insurance Verification",
        "platform": "sqli-labs",
        "level": "Less-13",
        "ground_truth": True,
        "vulnerability_type": "Stacked Query (POST)",
        "url": "http://192.168.10.20/sqli-labs/Less-13/",
        "medical_context": {
            "module": "Insurance Verification",
            "risk_level": "L3",
            "parameter": "insurance_member_id",
            "data_sensitivity": "MEDIUM"
        },
        "sqlmap_result": {
            "status_code": 200,
            "delay_time": 4.8,
            "error_keywords": [],
            "vulnerability_type": "",
            "successful_payloads": 3,
            "total_payloads": 20,
            "dbms_detected": False,
            "data_dumped": False,
            "parameter_name": "insurance_member_id"
        },
        "zap_result": {
            "status_code": 200,
            "response_time": 310,
            "content_length_change": 0.87,
            "alert_level": "High",
            "triggered_rules": 9,
            "total_rules": 10,
            "dbms_detected": True,
            "parameter_name": "insurance_member_id"
        },
    }
    test_cases["test_cases"].append(tc029)
    
    tc030 = {
        "id": "TC030",
        "name": "Sqli-labs SQL Injection - Lab Results Portal",
        "platform": "sqli-labs",
        "level": "Less-14",
        "ground_truth": True,
        "vulnerability_type": "Error-based (POST Double Quote)",
        "url": "http://192.168.10.20/sqli-labs/Less-12/",
        "medical_context": {
            "module": "Lab Results Portal",
            "risk_level": "L3",
            "parameter": "lab_tech_id",
            "data_sensitivity": "MEDIUM"
        },
        "sqlmap_result": {
            "status_code": 200,
            "delay_time": 4.5,
            "error_keywords": [],
            "vulnerability_type": "",
            "successful_payloads": 6,
            "total_payloads": 20,
            "dbms_detected": False,
            "data_dumped": False,
            "parameter_name": "lab_tech_id"
        },
        "zap_result": {
            "status_code": 200,
            "response_time": 290,
            "content_length_change": 0.78,
            "alert_level": "High",
            "triggered_rules": 8,
            "total_rules": 10,
            "dbms_detected": True,
            "parameter_name": "lab_tech_id"
        },
    }
    test_cases["test_cases"].append(tc030)
    
    tc031 = {
        "id": "TC031",
        "name": "Sqli-labs SQL Injection - Medical Imaging Access",
        "platform": "sqli-labs",
        "level": "Less-17",
        "ground_truth": True,
        "vulnerability_type": "Error-based (Password Update)",
        "url": "http://192.168.10.20/sqli-labs/Less-17/",
        "medical_context": {
            "module": "Medical Imaging Access",
            "risk_level": "L3",
            "parameter": "radiologist_id",
            "data_sensitivity": "MEDIUM"
        },
        "sqlmap_result": {
            "status_code": 200,
            "delay_time": 4.2,
            "error_keywords": [],
            "vulnerability_type": "",
            "successful_payloads": 2,
            "total_payloads": 20,
            "dbms_detected": False,
            "data_dumped": False,
            "parameter_name": "radiologist_id"
        },
        "zap_result": {
            "status_code": 200,
            "response_time": 300,
            "content_length_change": 0.72,
            "alert_level": "High",
            "triggered_rules": 8,
            "total_rules": 10,
            "dbms_detected": True,
            "parameter_name": "radiologist_id"
        },
    }
    test_cases["test_cases"].append(tc031)
    
    tc032 = {
        "id": "TC032",
        "name": "Sqli-labs SQL Injection - Billing System",
        "platform": "sqli-labs",
        "level": "Less-18",
        "ground_truth": True,
        "vulnerability_type": "Error-based (Header Injection)",
        "url": "http://192.168.10.20/sqli-labs/Less-18/",
        "medical_context": {
            "module": "Billing System",
            "risk_level": "L3",
            "parameter": "billing_record_id",
            "data_sensitivity": "MEDIUM"
        },
        "sqlmap_result": {
            "status_code": 200,
            "delay_time": 3.6,
            "error_keywords": [],
            "vulnerability_type": "",
            "successful_payloads": 3,
            "total_payloads": 20,
            "dbms_detected": False,
            "data_dumped": False,
            "parameter_name": "billing_record_id"
        },
        "zap_result": {
            "status_code": 200,
            "response_time": 240,
            "content_length_change": 0.75,
            "alert_level": "High",
            "triggered_rules": 8,
            "total_rules": 10,
            "dbms_detected": True,
            "parameter_name": "billing_record_id"
        },
    }
    test_cases["test_cases"].append(tc032)
    
    tc033 = {
        "id": "TC033",
        "name": "Sqli-labs SQL Injection - Insurance Claims",
        "platform": "sqli-labs",
        "level": "Less-19",
        "ground_truth": True,
        "vulnerability_type": "Error-based (Referer Injection)",
        "url": "http://192.168.10.20/sqli-labs/Less-19/",
        "medical_context": {
            "module": "Insurance Claims",
            "risk_level": "L3",
            "parameter": "claim_submission_id",
            "data_sensitivity": "MEDIUM"
        },
        "sqlmap_result": {
            "status_code": 200,
            "delay_time": 4.1,
            "error_keywords": [],
            "vulnerability_type": "",
            "successful_payloads": 1,
            "total_payloads": 20,
            "dbms_detected": False,
            "data_dumped": False,
            "parameter_name": "claim_submission_id"
        },
        "zap_result": {
            "status_code": 200,
            "response_time": 230,
            "content_length_change": 0.83,
            "alert_level": "High",
            "triggered_rules": 7,
            "total_rules": 10,
            "dbms_detected": True,
            "parameter_name": "claim_submission_id"
        },
    }
    test_cases["test_cases"].append(tc033)
    
    tc034 = {
        "id": "TC034",
        "name": "Sqli-labs SQL Injection - Nurse Station System",
        "platform": "sqli-labs",
        "level": "Less-20",
        "ground_truth": True,
        "vulnerability_type": "Error-based (Cookie Injection)",
        "url": "http://192.168.10.20/sqli-labs/Less-20/",
        "medical_context": {
            "module": "Nurse Station System",
            "risk_level": "L4",
            "parameter": "nurse_schedule_id",
            "data_sensitivity": "LOW"
        },
        "sqlmap_result": {
            "status_code": 200,
            "delay_time": 3.2,
            "error_keywords": ["Cookie"],
            "vulnerability_type": "Error-based (Cookie Injection)",
            "successful_payloads": 14,
            "total_payloads": 20,
            "dbms_detected": True,
            "data_dumped": False,
            "parameter_name": "nurse_schedule_id"
        },
        "zap_result": {
            "status_code": 200,
            "response_time": 538,
            "content_length_change": 0.52,
            "alert_level": "Medium",
            "triggered_rules": 6,
            "total_rules": 10,
            "dbms_detected": True,
            "parameter_name": "nurse_schedule_id"
        },
    }
    test_cases["test_cases"].append(tc034)
    
    tc035 = {
        "id": "TC035",
        "name": "Sqli-labs SQL Injection - Equipment Maintenance",
        "platform": "sqli-labs",
        "level": "Less-23",
        "ground_truth": True,
        "vulnerability_type": "Error-based (Comments)",
        "url": "http://192.168.10.20/sqli-labs/Less-23/",
        "medical_context": {
            "module": "Equipment Maintenance",
            "risk_level": "L4",
            "parameter": "equipment_log_id",
            "data_sensitivity": "LOW"
        },
        "sqlmap_result": {
            "status_code": 200,
            "delay_time": 4.3,
            "error_keywords": ["GTID_SUBSET", "MySQL"],
            "vulnerability_type": "Error-based (Comments)",
            "successful_payloads": 14,
            "total_payloads": 20,
            "dbms_detected": True,
            "data_dumped": False,
            "parameter_name": "equipment_log_id"
        },
        "zap_result": {
            "status_code": 200,
            "response_time": 301,
            "content_length_change": 0.52,
            "alert_level": "Medium",
            "triggered_rules": 6,
            "total_rules": 10,
            "dbms_detected": True,
            "parameter_name": "equipment_log_id"
        },
    }
    test_cases["test_cases"].append(tc035)
    
    # False Positive
    tc036 = {
        "id": "TC036",
        "name": "DVWA High Security - False Positive Test",
        "platform": "DVWA",
        "level": "SQL Injection",
        "security_level": "High",
        "ground_truth": False,
        "vulnerability_type": "None",
        "url": "http://192.168.10.20/DVWA/vulnerabilities/sqli/?id=1&Submit=Submit#",
        "medical_context": {
            "module": "Patient ID Validation",
            "risk_level": "L2",
            "parameter": "patient_national_id",
            "data_sensitivity": "HIGH"
        },
        "sqlmap_result": {
            "status_code": 200,
            "delay_time": 0.1,
            "error_keywords": [],
            "vulnerability_type": "",
            "successful_payloads": 0,
            "total_payloads": 20,
            "dbms_detected": False,
            "data_dumped": False,
            "parameter_name": "patient_national_id"
        },
        "zap_result": {
            "status_code": 200,
            "response_time": 250,
            "content_length_change": 0.01,
            "alert_level": "Low",
            "triggered_rules": 0,
            "total_rules": 10,
            "dbms_detected": False,
            "parameter_name": "patient_national_id"
        }
    }
    test_cases["test_cases"].append(tc036)
    
    tc037 = {
        "id": "TC037",
        "name": "DVWA High Security - False Positive Test",
        "platform": "DVWA",
        "level": "SQL Injection Blind",
        "security_level": "High",
        "ground_truth": False,
        "vulnerability_type": "None",
        "url": "http://192.168.10.20/DVWA/vulnerabilities/sqli/?id=1&Submit=Submit#",
        "medical_context": {
            "module": "Medical Record Query",
            "risk_level": "L3",
            "parameter": "medical_record_id",
            "data_sensitivity": "HIGH"
        },
        "sqlmap_result": {
            "status_code": 200,
            "delay_time": 0.1,
            "error_keywords": [],
            "vulnerability_type": "",
            "successful_payloads": 0,
            "total_payloads": 20,
            "dbms_detected": False,
            "data_dumped": False,
            "parameter_name": "medical_record_id"
        },
        "zap_result": {
            "status_code": 200,
            "response_time": 270,
            "content_length_change": 0.01,
            "alert_level": "Low",
            "triggered_rules": 0,
            "total_rules": 10,
            "dbms_detected": False,
            "parameter_name": "medical_record_id"
        }
    }
    test_cases["test_cases"].append(tc037)
    
    tc038 = {
        "id": "TC038",
        "name": "Sqli-labs High Security - False Positive Test",
        "platform": "sqli-labs",
        "level": "Less-1",
        "security_level": "High",
        "ground_truth": False,
        "vulnerability_type": "None",
        "url": "http://192.168.10.20/sqli-labs/Less-1/?id=1'",
        "medical_context": {
            "module": "Patient Name Search",
            "risk_level": "L4",
            "parameter": "patient_name",
            "data_sensitivity": "HIGH"
        },
        "sqlmap_result": {
            "status_code": 200,
            "delay_time": 0.1,
            "error_keywords": [],
            "vulnerability_type": "",
            "successful_payloads": 0,
            "total_payloads": 20,
            "dbms_detected": False,
            "data_dumped": False,
            "parameter_name": "patient_name"
        },
        "zap_result": {
            "status_code": 200,
            "response_time": 50,
            "content_length_change": 0.01,
            "alert_level": "Low",
            "triggered_rules": 0,
            "total_rules": 10,
            "dbms_detected": False,
            "parameter_name": "patient_name"
        }
    }
    test_cases["test_cases"].append(tc038)
    
    tc039 = {
        "id": "TC039",
        "name": "Sqli-labs High Security - False Positive Test",
        "platform": "sqli-labs",
        "level": "Less-8",
        "security_level": "High",
        "ground_truth": False,
        "vulnerability_type": "None",
        "url": "http://192.168.10.20/sqli-labs/Less-8/?id=1",
        "medical_context": {
            "module": "Appointment Status",
            "risk_level": "L4",
            "parameter": "appointment_status",
            "data_sensitivity": "HIGH"
        },
        "sqlmap_result": {
            "status_code": 200,
            "delay_time": 0.1,
            "error_keywords": [],
            "vulnerability_type": "",
            "successful_payloads": 0,
            "total_payloads": 20,
            "dbms_detected": False,
            "data_dumped": False,
            "parameter_name": "appointment_status"
        },
        "zap_result": {
            "status_code": 200,
            "response_time": 70,
            "content_length_change": 0.01,
            "alert_level": "Informational",
            "triggered_rules": 0,
            "total_rules": 10,
            "dbms_detected": False,
            "parameter_name": "appointment_status"
        }
    }
    test_cases["test_cases"].append(tc039)
    
    tc040 = {
        "id": "TC040",
        "name": "Sqli-labs High Security - False Positive Test",
        "platform": "sqli-labs",
        "level": "Less-11 (POST)",
        "security_level": "High",
        "ground_truth": False,
        "vulnerability_type": "None",
        "url": "http://192.168.10.20/sqli-labs/Less-11/",
        "medical_context": {
            "module": "Password Change",
            "risk_level": "L2",
            "parameter": "user_password",
            "data_sensitivity": "HIGH"
        },
        "sqlmap_result": {
            "status_code": 200,
            "delay_time": 0.1,
            "error_keywords": [],
            "vulnerability_type": "",
            "successful_payloads": 0,
            "total_payloads": 20,
            "dbms_detected": False,
            "data_dumped": False,
            "parameter_name": "user_password"
        },
        "zap_result": {
            "status_code": 200,
            "response_time": 90,
            "content_length_change": 0.01,
            "alert_level": "Informational",
            "triggered_rules": 2,
            "total_rules": 10,
            "dbms_detected": False,
            "parameter_name": "user_password"
        }
    }
    test_cases["test_cases"].append(tc040)
    
    tc041 = {
        "id": "TC041",
        "name": "Prepared Statement - Electronic Prescription Query",
        "platform": "Custom",
        "level": "SQL Injection",
        "security_level": "High",
        "ground_truth": False, 
        "vulnerability_type": "None",
        "url": "http://192.168.10.20/medical-app/prescription/query",
        "medical_context": {
            "module": "Electronic Prescription System",
            "risk_level": "L1",
            "parameter": "prescription_id",
            "data_sensitivity": "CRITICAL"
        },
        "sqlmap_result": {
            "status_code": 200,
            "delay_time": 5.8,
            "error_keywords": ["MySQL","syntax error","query"],
            "vulnerability_type": "",
            "successful_payloads": 9,
            "total_payloads": 20,
            "dbms_detected": False,
            "data_dumped": False,
            "parameter_name": "prescription_id"
        },
        "zap_result": {
            "status_code": 200,
            "response_time": 400,
            "content_length_change": 0.3,
            "alert_level": "High",
            "triggered_rules": 5,
            "total_rules": 10,
            "dbms_detected": False,
            "parameter_name": "prescription_id"
        }
    }
    test_cases["test_cases"].append(tc041)
    
    tc042 = {
        "id": "TC042",
        "name": "Prepared Statement - Patient Medical Record Access",
        "platform": "Custom",
        "level": "SQL Injection",
        "security_level": "High",
        "ground_truth": False,
        "vulnerability_type": "None",
        "url": "http://192.168.10.20/medical-app/records/view",
        "medical_context": {
            "module": "Patient Medical History",
            "risk_level": "L2",
            "parameter": "patient_record_id",
            "data_sensitivity": "HIGH"
        },
        "sqlmap_result": {
            "status_code": 200,
            "delay_time": 0.3,
            "error_keywords": [],
            "vulnerability_type": "",
            "successful_payloads": 0,
            "total_payloads": 20,
            "dbms_detected": False,
            "data_dumped": False,
            "parameter_name": "patient_record_id"
        },
        "zap_result": {
            "status_code": 200,
            "response_time": 180,
            "content_length_change": 0.02,
            "alert_level": "Low",
            "triggered_rules": 1,
            "total_rules": 10,
            "dbms_detected": False,
            "parameter_name": "patient_record_id"
        }
    }
    test_cases["test_cases"].append(tc042)
    
    tc043 = {
        "id": "TC043",
        "name": "Prepared Statement - Lab Results Portal",
        "platform": "Custom",
        "level": "SQL Injection",
        "security_level": "High",
        "ground_truth": False,
        "vulnerability_type": "None",
        "url": "http://192.168.10.20/medical-app/lab/results",
        "medical_context": {
            "module": "Lab Results Portal",
            "risk_level": "L3",
            "parameter": "lab_test_id",
            "data_sensitivity": "MEDIUM"
        },
        "sqlmap_result": {
            "status_code": 200,
            "delay_time": 0.25,
            "error_keywords": [],
            "vulnerability_type": "",
            "successful_payloads": 0,
            "total_payloads": 20,
            "dbms_detected": False,
            "data_dumped": False,
            "parameter_name": "lab_test_id"
        },
        "zap_result": {
            "status_code": 200,
            "response_time": 160,
            "content_length_change": 0.03,
            "alert_level": "Informational",
            "triggered_rules": 0,
            "total_rules": 10,
            "dbms_detected": False,
            "parameter_name": "lab_test_id"
        }
    }
    test_cases["test_cases"].append(tc043)
    
    tc044 = {
        "id": "TC044",
        "name": "Prepared Statement - Appointment System",
        "platform": "Custom",
        "level": "SQL Injection",
        "security_level": "High",
        "ground_truth": False,
        "vulnerability_type": "None",
        "url": "http://192.168.10.20/medical-app/appointment/book",
        "medical_context": {
            "module": "Appointment Scheduling",
            "risk_level": "L4",
            "parameter": "appointment_id",
            "data_sensitivity": "LOW"
        },
        "sqlmap_result": {
            "status_code": 200,
            "delay_time": 0.15,
            "error_keywords": [],
            "vulnerability_type": "",
            "successful_payloads": 0,
            "total_payloads": 20,
            "dbms_detected": False,
            "data_dumped": False,
            "parameter_name": "appointment_id"
        },
        "zap_result": {
            "status_code": 200,
            "response_time": 120,
            "content_length_change": 0.01,
            "alert_level": "Informational",
            "triggered_rules": 0,
            "total_rules": 10,
            "dbms_detected": False,
            "parameter_name": "appointment_id"
        }
    }
    test_cases["test_cases"].append(tc044)
    
    tc045 = {
        "id": "TC045",
        "name": "Prepared Statement - Doctor Availability Check",
        "platform": "Custom",
        "level": "SQL Injection",
        "security_level": "High",
        "ground_truth": False,
        "vulnerability_type": "None",
        "url": "http://192.168.10.20/medical-app/doctor/availability",
        "medical_context": {
            "module": "Department Directory",
            "risk_level": "L4",
            "parameter": "doctor_id",
            "data_sensitivity": "LOW"
        },
        "sqlmap_result": {
            "status_code": 200,
            "delay_time": 0.18,
            "error_keywords": [],
            "vulnerability_type": "",
            "successful_payloads": 0,
            "total_payloads": 20,
            "dbms_detected": False,
            "data_dumped": False,
            "parameter_name": "doctor_id"
        },
        "zap_result": {
            "status_code": 200,
            "response_time": 140,
            "content_length_change": 0.02,
            "alert_level": "Low",
            "triggered_rules": 1,
            "total_rules": 10,
            "dbms_detected": False,
            "parameter_name": "doctor_id"
        }
    }
    test_cases["test_cases"].append(tc045)
    
    tc046 = {
        "id": "TC046",
        "name": "Whitelist Validation - Patient ID Format Check",
        "platform": "Custom",
        "level": "SQL Injection",
        "security_level": "Medium",
        "ground_truth": False,
        "vulnerability_type": "None",
        "url": "http://192.168.10.20/medical-app/patient/search",
        "medical_context": {
            "module": "Patient Information Query",
            "risk_level": "L2",
            "parameter": "patient_national_id",
            "data_sensitivity": "HIGH"
        },
        "sqlmap_result": {
            "status_code": 200,
            "delay_time": 4.8,
            "error_keywords": ["SELECT", "FROM", "WHERE", "MySQL", "syntax", "query"],
            "vulnerability_type": "Boolean-based blind",
            "successful_payloads": 8,
            "total_payloads": 20,
            "dbms_detected": True,
            "data_dumped": False,
            "parameter_name": "patient_national_id"
        },
        "zap_result": {
            "status_code": 200,
            "response_time": 420,
            "content_length_change": 0.38,
            "alert_level": "High",
            "triggered_rules": 7,
            "total_rules": 10,
            "dbms_detected": True,
            "parameter_name": "patient_national_id"
        }
    }
    test_cases["test_cases"].append(tc046)
    
    tc047 = {
        "id": "TC047",
        "name": "Regex Validation - Insurance Member ID",
        "platform": "Custom",
        "level": "SQL Injection",
        "security_level": "Medium",
        "ground_truth": False,
        "vulnerability_type": "None",
        "url": "http://192.168.10.20/medical-app/insurance/verify",
        "medical_context": {
            "module": "Insurance Verification",
            "risk_level": "L3",
            "parameter": "insurance_member_id",
            "data_sensitivity": "MEDIUM"
        },
        "sqlmap_result": {
            "status_code": 200,
            "delay_time": 8.5,
            "error_keywords": ["SELECT", "SLEEP", "time", "delay", "MySQL"],
            "vulnerability_type": "Time-based blind",
            "successful_payloads": 12,
            "total_payloads": 20,
            "dbms_detected": True,
            "data_dumped": False,
            "parameter_name": "insurance_member_id"
        },
        "zap_result": {
            "status_code": 200,
            "response_time": 380,
            "content_length_change": 0.33,
            "alert_level": "Medium",
            "triggered_rules": 6,
            "total_rules": 10,
            "dbms_detected": True,
            "parameter_name": "insurance_member_id"
        }
    }
    test_cases["test_cases"].append(tc047)
    
    tc048 = {
        "id": "TC048",
        "name": "Integer-Only Validation - Room Number",
        "platform": "Custom",
        "level": "SQL Injection",
        "security_level": "Medium",
        "ground_truth": False,
        "vulnerability_type": "None",
        "url": "http://192.168.10.20/medical-app/room/status",
        "medical_context": {
            "module": "Room Assignment",
            "risk_level": "L4",
            "parameter": "room_number",
            "data_sensitivity": "LOW"
        },
        "sqlmap_result": {
            "status_code": 200,
            "delay_time": 2.5,
            "error_keywords": [],
            "vulnerability_type": "",
            "successful_payloads": 3,
            "total_payloads": 20,
            "dbms_detected": False,
            "data_dumped": False,
            "parameter_name": "room_number"
        },
        "zap_result": {
            "status_code": 200,
            "response_time": 335,
            "content_length_change": 0.48,
            "alert_level": "Low",
            "triggered_rules": 3,
            "total_rules": 10,
            "dbms_detected": False,
            "parameter_name": "room_number"
        }
    }
    test_cases["test_cases"].append(tc048)
    
    tc049 = {
        "id": "TC049",
        "name": "Django ORM - Diagnosis Records Query",
        "platform": "Custom",
        "level": "SQL Injection",
        "security_level": "High",
        "ground_truth": False,
        "vulnerability_type": "None",
        "url": "http://192.168.10.20/medical-app/diagnosis/list",
        "medical_context": {
            "module": "Diagnosis Records",
            "risk_level": "L2",
            "parameter": "diagnosis_id",
            "data_sensitivity": "HIGH"
        },
        "sqlmap_result": {
            "status_code": 200,
            "delay_time": 8.8,
            "error_keywords": ["UNION", "SELECT", "NULL", "column", "mismatch", "MySQL", "syntax error", 
                            "query", "database", "operand"],
            "vulnerability_type": "UNION query",
            "successful_payloads": 18,
            "total_payloads": 20,
            "dbms_detected": True,
            "data_dumped": True,
            "parameter_name": "diagnosis_id"
        },
        "zap_result": {
            "status_code": 200,
            "response_time": 770,
            "content_length_change": 0.92,
            "alert_level": "High",
            "triggered_rules": 10,
            "total_rules": 10,
            "dbms_detected": True,
            "parameter_name": "diagnosis_id"
        }
    }
    test_cases["test_cases"].append(tc049)
    
    tc050 = {
        "id": "TC050",
        "name": "Hibernate ORM - Medical Imaging Access",
        "platform": "Custom",
        "level": "SQL Injection",
        "security_level": "High",
        "ground_truth": False,
        "vulnerability_type": "None",
        "url": "http://192.168.10.20/medical-app/imaging/view",
        "medical_context": {
            "module": "Medical Imaging System",
            "risk_level": "L3",
            "parameter": "imaging_study_id",
            "data_sensitivity": "MEDIUM"
        },
        "sqlmap_result": {
            "status_code": 200,
            "delay_time": 4.8,
            "error_keywords": ["server", "database","query","SELECT", "WHERE"],
            "vulnerability_type": "Boolean-based blind",
            "successful_payloads": 9,
            "total_payloads": 20,
            "dbms_detected": True,
            "data_dumped": False,
            "parameter_name": "imaging_study_id"
        },
        "zap_result": {
            "status_code": 200,
            "response_time": 320,
            "content_length_change": 0.32,
            "alert_level": "Medium",
            "triggered_rules": 6,
            "total_rules": 10,
            "dbms_detected": True,
            "parameter_name": "imaging_study_id"
        }
    }
    test_cases["test_cases"].append(tc050)
    
    tc051 = {
        "id": "TC051",
        "name": "WAF Protected - Surgical Record Query",
        "platform": "Custom",
        "level": "SQL Injection",
        "security_level": "High",
        "ground_truth": False,
        "vulnerability_type": "None",
        "url": "http://192.168.10.20/medical-app/surgery/records",
        "medical_context": {
            "module": "Surgical Record System",
            "risk_level": "L1",
            "parameter": "surgery_record_id",
            "data_sensitivity": "CRITICAL"
        },
        "sqlmap_result": {
            "status_code": 403,
            "delay_time": 0.1,
            "error_keywords": [],
            "vulnerability_type": "",
            "successful_payloads": 0,
            "total_payloads": 20,
            "dbms_detected": False,
            "data_dumped": False,
            "parameter_name": "surgery_record_id"
        },
        "zap_result": {
            "status_code": 403,
            "response_time": 80,
            "content_length_change": 0.0,
            "alert_level": "Informational",
            "triggered_rules": 0,
            "total_rules": 10,
            "dbms_detected": False,
            "parameter_name": "surgery_record_id"
        }
    }
    test_cases["test_cases"].append(tc051)
    
    tc052 = {
        "id": "TC052",
        "name": "ModSecurity WAF - Authentication System",
        "platform": "Custom",
        "level": "SQL Injection",
        "security_level": "High",
        "ground_truth": False,
        "vulnerability_type": "None",
        "url": "http://192.168.10.20/medical-app/auth/login",
        "medical_context": {
            "module": "Authentication System",
            "risk_level": "L2",
            "parameter": "username",
            "data_sensitivity": "HIGH"
        },
        "sqlmap_result": {
            "status_code": 403,
            "delay_time": 0.12,
            "error_keywords": [],
            "vulnerability_type": "",
            "successful_payloads": 0,
            "total_payloads": 20,
            "dbms_detected": False,
            "data_dumped": False,
            "parameter_name": "username"
        },
        "zap_result": {
            "status_code": 403,
            "response_time": 90,
            "content_length_change": 0.0,
            "alert_level": "Low",
            "triggered_rules": 1,
            "total_rules": 10,
            "dbms_detected": False,
            "parameter_name": "username"
        }
    }
    test_cases["test_cases"].append(tc052)
    
    tc053 = {
        "id": "TC053",
        "name": "Stored Procedure - HIV Test Records",
        "platform": "Custom",
        "level": "SQL Injection",
        "security_level": "High",
        "ground_truth": False,
        "vulnerability_type": "None",
        "url": "http://192.168.10.20/medical-app/hiv/records",
        "medical_context": {
            "module": "HIV Status Records",
            "risk_level": "L1",
            "parameter": "hiv_test_id",
            "data_sensitivity": "CRITICAL"
        },
        "sqlmap_result": {
            "status_code": 200,
            "delay_time": 0.25,
            "error_keywords": [],
            "vulnerability_type": "",
            "successful_payloads": 0,
            "total_payloads": 20,
            "dbms_detected": False,
            "data_dumped": False,
            "parameter_name": "hiv_test_id"
        },
        "zap_result": {
            "status_code": 200,
            "response_time": 155,
            "content_length_change": 0.02,
            "alert_level": "Informational",
            "triggered_rules": 0,
            "total_rules": 10,
            "dbms_detected": False,
            "parameter_name": "hiv_test_id"
        }
    }
    test_cases["test_cases"].append(tc053)
    
    tc054 = {
        "id": "TC054",
        "name": "Stored Procedure - Billing Calculation",
        "platform": "Custom",
        "level": "SQL Injection",
        "security_level": "High",
        "ground_truth": False,
        "vulnerability_type": "None",
        "url": "http://192.168.10.20/medical-app/billing/calculate",
        "medical_context": {
            "module": "Billing System",
            "risk_level": "L3",
            "parameter": "billing_record_id",
            "data_sensitivity": "MEDIUM"
        },
        "sqlmap_result": {
            "status_code": 200,
            "delay_time": 0.3,
            "error_keywords": [],
            "vulnerability_type": "",
            "successful_payloads": 0,
            "total_payloads": 20,
            "dbms_detected": False,
            "data_dumped": False,
            "parameter_name": "billing_record_id"
        },
        "zap_result": {
            "status_code": 200,
            "response_time": 175,
            "content_length_change": 0.03,
            "alert_level": "Low",
            "triggered_rules": 1,
            "total_rules": 10,
            "dbms_detected": False,
            "parameter_name": "billing_record_id"
        }
    }
    test_cases["test_cases"].append(tc054)
    
    tc055 = {
        "id": "TC055",
        "name": "Generic Error Messages - Equipment Maintenance",
        "platform": "Custom",
        "level": "SQL Injection",
        "security_level": "Medium",
        "ground_truth": False,
        "vulnerability_type": "None",
        "url": "http://192.168.10.20/medical-app/equipment/status",
        "medical_context": {
            "module": "Equipment Maintenance",
            "risk_level": "L4",
            "parameter": "equipment_log_id",
            "data_sensitivity": "LOW"
        },
        "sqlmap_result": {
            "status_code": 200,
            "delay_time": 0.2,
            "error_keywords": [],
            "vulnerability_type": "",
            "successful_payloads": 0,
            "total_payloads": 20,
            "dbms_detected": False,
            "data_dumped": False,
            "parameter_name": "equipment_log_id"
        },
        "zap_result": {
            "status_code": 200,
            "response_time": 145,
            "content_length_change": 0.02,
            "alert_level": "Low",
            "triggered_rules": 1,
            "total_rules": 10,
            "dbms_detected": False,
            "parameter_name": "equipment_log_id"
        }
    }
    test_cases["test_cases"].append(tc055)
    

    print(f"Generated {len(test_cases['test_cases'])} medical test case examples.")
    return test_cases

def save_test_cases(output_file="medical_sql_injection_testcases.json"):
    test_cases = generate_test_cases()
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(test_cases, f, indent=2, ensure_ascii=False)
    
    print(f"\nThe test case has been saved to: {output_file}")

if __name__ == "__main__":
    save_test_cases()