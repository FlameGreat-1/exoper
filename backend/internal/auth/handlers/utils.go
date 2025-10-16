package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func generateRequestID() string {
	timestamp := time.Now().Format("20060102150405")
	randomBytes := make([]byte, 4)
	rand.Read(randomBytes)
	randomHex := hex.EncodeToString(randomBytes)
	return fmt.Sprintf("%s-%s", timestamp, randomHex)
}

func sanitizeString(input string) string {
	input = strings.TrimSpace(input)
	input = strings.ReplaceAll(input, "\n", "")
	input = strings.ReplaceAll(input, "\r", "")
	input = strings.ReplaceAll(input, "\t", "")
	return input
}

func validateEmail(email string) bool {
	if email == "" {
		return false
	}
	
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return false
	}
	
	if len(parts[0]) == 0 || len(parts[1]) == 0 {
		return false
	}
	
	return strings.Contains(parts[1], ".")
}

func convertMapToStructPB(m map[string]interface{}) (*structpb.Struct, error) {
	if m == nil {
		return nil, nil
	}
	return structpb.NewStruct(m)
}

func convertStructPBToMap(s *structpb.Struct) map[string]interface{} {
	if s == nil {
		return make(map[string]interface{})
	}
	return s.AsMap()
}

func convertTimePointerToTimestamp(t *time.Time) *timestamppb.Timestamp {
	if t == nil {
		return nil
	}
	return timestamppb.New(*t)
}

func convertTimestampToTimePointer(ts *timestamppb.Timestamp) *time.Time {
	if ts == nil {
		return nil
	}
	t := ts.AsTime()
	return &t
}

func maskSensitiveData(data string) string {
	if len(data) <= 8 {
		return strings.Repeat("*", len(data))
	}
	
	prefix := data[:4]
	suffix := data[len(data)-4:]
	middle := strings.Repeat("*", len(data)-8)
	
	return prefix + middle + suffix
}

func truncateString(s string, maxLength int) string {
	if len(s) <= maxLength {
		return s
	}
	
	if maxLength <= 3 {
		return s[:maxLength]
	}
	
	return s[:maxLength-3] + "..."
}

func isValidUUID(uuid string) bool {
	if len(uuid) != 36 {
		return false
	}
	
	parts := strings.Split(uuid, "-")
	if len(parts) != 5 {
		return false
	}
	
	expectedLengths := []int{8, 4, 4, 4, 12}
	for i, part := range parts {
		if len(part) != expectedLengths[i] {
			return false
		}
		
		for _, char := range part {
			if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f') || (char >= 'A' && char <= 'F')) {
				return false
			}
		}
	}
	
	return true
}

func normalizeScope(scope string) string {
	return strings.ToLower(strings.TrimSpace(scope))
}

func normalizePermission(permission string) string {
	return strings.ToLower(strings.TrimSpace(permission))
}

func mergeStringSlices(slice1, slice2 []string) []string {
	seen := make(map[string]bool)
	result := []string{}
	
	for _, item := range slice1 {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	
	for _, item := range slice2 {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	
	return result
}

func containsString(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func removeStringFromSlice(slice []string, item string) []string {
	result := []string{}
	for _, s := range slice {
		if s != item {
			result = append(result, s)
		}
	}
	return result
}
