# RED manifest: go/guardian/profile validator

| test | break implementation | expected failure |
|------|------------------------|------------------|
| TestValidateProfile_rejects_empty_object | make validateProfile always return nil | accepts {} |
| TestValidateProfile_rejects_invalid_json | skip json.Unmarshal error check | accepts invalid JSON |
