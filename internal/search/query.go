package search

import (
	"strings"
)

type Filter struct {
	Field string `json:"field"`
	Value string `json:"value"`
}

type ParsedQuery struct {
	RawQuery   string   `json:"raw_query"`
	Filters    []Filter `json:"filters"`
	FreeText   string   `json:"free_text"`
}

func ParseQuery(raw string) ParsedQuery {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ParsedQuery{}
	}

	tokens := strings.Fields(raw)
	filters := make([]Filter, 0)
	freeTextParts := make([]string, 0)

	for _, token := range tokens {
		if strings.Contains(token, ":") {
			parts := strings.SplitN(token, ":", 2)
			field := strings.ToLower(strings.TrimSpace(parts[0]))
			val := strings.Trim(strings.TrimSpace(parts[1]), "\"")
			if field != "" && val != "" {
				filters = append(filters, Filter{
					Field: field,
					Value: val,
				})
				continue
			}
		}
		freeTextParts = append(freeTextParts, token)
	}

	return ParsedQuery{
		RawQuery: raw,
		Filters:  filters,
		FreeText: strings.Join(freeTextParts, " "),
	}
}
