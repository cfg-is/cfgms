package templates

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

// InMemoryTemplateStore provides an in-memory implementation of TemplateStore
type InMemoryTemplateStore struct {
	mu        sync.RWMutex
	templates map[string]*Template
}

// NewInMemoryTemplateStore creates a new in-memory template store
func NewInMemoryTemplateStore() TemplateStore {
	return &InMemoryTemplateStore{
		templates: make(map[string]*Template),
	}
}

// Get retrieves a template by ID
func (s *InMemoryTemplateStore) Get(ctx context.Context, id string) (*Template, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	template, exists := s.templates[id]
	if !exists {
		return nil, &TemplateError{
			Type:    "TEMPLATE_NOT_FOUND",
			Message: fmt.Sprintf("Template '%s' not found", id),
		}
	}
	
	// Return a copy to prevent external modifications
	return s.copyTemplate(template), nil
}

// Save saves a template
func (s *InMemoryTemplateStore) Save(ctx context.Context, template *Template) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	if template.ID == "" {
		return &TemplateError{
			Type:    "INVALID_TEMPLATE",
			Message: "Template ID cannot be empty",
		}
	}
	
	// Update timestamp
	template.UpdatedAt = time.Now()
	
	// Store a copy to prevent external modifications
	s.templates[template.ID] = s.copyTemplate(template)
	
	return nil
}

// Delete deletes a template
func (s *InMemoryTemplateStore) Delete(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	if _, exists := s.templates[id]; !exists {
		return &TemplateError{
			Type:    "TEMPLATE_NOT_FOUND",
			Message: fmt.Sprintf("Template '%s' not found", id),
		}
	}
	
	delete(s.templates, id)
	return nil
}

// List lists templates matching the filter
func (s *InMemoryTemplateStore) List(ctx context.Context, filter TemplateFilter) ([]*Template, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	var results []*Template
	
	for _, template := range s.templates {
		if s.matchesFilter(template, filter) {
			results = append(results, s.copyTemplate(template))
		}
		
		// Apply limit
		if filter.Limit > 0 && len(results) >= filter.Limit {
			break
		}
	}
	
	// Apply offset
	if filter.Offset > 0 && filter.Offset < len(results) {
		results = results[filter.Offset:]
	}
	
	return results, nil
}

// Exists checks if a template exists
func (s *InMemoryTemplateStore) Exists(ctx context.Context, id string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	_, exists := s.templates[id]
	return exists, nil
}

// Helper methods

func (s *InMemoryTemplateStore) matchesFilter(template *Template, filter TemplateFilter) bool {
	// Check name pattern
	if filter.NamePattern != "" {
		if !strings.Contains(strings.ToLower(template.Name), strings.ToLower(filter.NamePattern)) {
			return false
		}
	}
	
	// Check tags
	if len(filter.Tags) > 0 {
		hasMatchingTag := false
		for _, filterTag := range filter.Tags {
			for _, templateTag := range template.Tags {
				if strings.EqualFold(filterTag, templateTag) {
					hasMatchingTag = true
					break
				}
			}
			if hasMatchingTag {
				break
			}
		}
		if !hasMatchingTag {
			return false
		}
	}
	
	// Check created after
	if filter.CreatedAfter != nil && template.CreatedAt.Before(*filter.CreatedAfter) {
		return false
	}
	
	// Check created before
	if filter.CreatedBefore != nil && template.CreatedAt.After(*filter.CreatedBefore) {
		return false
	}
	
	return true
}

func (s *InMemoryTemplateStore) copyTemplate(template *Template) *Template {
	if template == nil {
		return nil
	}
	
	// Deep copy the template
	copyTemplate := &Template{
		ID:          template.ID,
		Name:        template.Name,
		Content:     make([]byte, len(template.Content)),
		Variables:   make(map[string]interface{}),
		Extends:     template.Extends,
		Includes:    make([]string, len(template.Includes)),
		Version:     template.Version,
		Description: template.Description,
		Tags:        make([]string, len(template.Tags)),
		CreatedAt:   template.CreatedAt,
		UpdatedAt:   template.UpdatedAt,
		Metadata:    make(map[string]interface{}),
	}
	
	// Copy byte slice
	copy(copyTemplate.Content, template.Content)
	
	// Copy variables
	for k, v := range template.Variables {
		copyTemplate.Variables[k] = v
	}
	
	// Copy includes
	copy(copyTemplate.Includes, template.Includes)
	
	// Copy tags
	copy(copyTemplate.Tags, template.Tags)
	
	// Copy metadata
	for k, v := range template.Metadata {
		copyTemplate.Metadata[k] = v
	}
	
	return copyTemplate
}

// GitTemplateStore provides a Git-backed implementation of TemplateStore
type GitTemplateStore struct {
	gitManager interface{} // Would be git.GitManager in real implementation
	repoID     string
	basePath   string
}

// NewGitTemplateStore creates a new Git-backed template store
func NewGitTemplateStore(gitManager interface{}, repoID string, basePath string) TemplateStore {
	return &GitTemplateStore{
		gitManager: gitManager,
		repoID:     repoID,
		basePath:   basePath,
	}
}

// Get retrieves a template from Git
func (s *GitTemplateStore) Get(ctx context.Context, id string) (*Template, error) {
	// In a real implementation, this would:
	// 1. Construct the file path from template ID
	// 2. Use gitManager.GetConfiguration() to read the template
	// 3. Parse the template content
	// 4. Return the Template object
	
	return nil, &TemplateError{
		Type:    "NOT_IMPLEMENTED",
		Message: "Git template store not yet implemented",
	}
}

// Save saves a template to Git
func (s *GitTemplateStore) Save(ctx context.Context, template *Template) error {
	// In a real implementation, this would:
	// 1. Serialize the template to YAML/JSON
	// 2. Use gitManager.SaveConfiguration() to write the template
	// 3. Commit the changes
	
	return &TemplateError{
		Type:    "NOT_IMPLEMENTED",
		Message: "Git template store not yet implemented",
	}
}

// Delete deletes a template from Git
func (s *GitTemplateStore) Delete(ctx context.Context, id string) error {
	// In a real implementation, this would:
	// 1. Use gitManager.DeleteConfiguration() to remove the template
	// 2. Commit the changes
	
	return &TemplateError{
		Type:    "NOT_IMPLEMENTED",
		Message: "Git template store not yet implemented",
	}
}

// List lists templates from Git
func (s *GitTemplateStore) List(ctx context.Context, filter TemplateFilter) ([]*Template, error) {
	// In a real implementation, this would:
	// 1. List all template files in the Git repository
	// 2. Load and parse each template
	// 3. Apply filters
	// 4. Return matching templates
	
	return nil, &TemplateError{
		Type:    "NOT_IMPLEMENTED",
		Message: "Git template store not yet implemented",
	}
}

// Exists checks if a template exists in Git
func (s *GitTemplateStore) Exists(ctx context.Context, id string) (bool, error) {
	// In a real implementation, this would check if the template file exists
	
	return false, &TemplateError{
		Type:    "NOT_IMPLEMENTED",
		Message: "Git template store not yet implemented",
	}
}