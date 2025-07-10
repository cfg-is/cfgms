package service

import (
	"context"

	"github.com/cfgis/cfgms/api/proto/controller"
	"github.com/cfgis/cfgms/features/rbac"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// RBACService implements the RBAC gRPC service
type RBACService struct {
	controller.UnimplementedRBACServiceServer
	rbacManager rbac.RBACManager
}

// NewRBACService creates a new RBAC service
func NewRBACService(rbacManager rbac.RBACManager) *RBACService {
	return &RBACService{
		rbacManager: rbacManager,
	}
}

// Permission Management

func (s *RBACService) GetPermission(ctx context.Context, req *controller.GetPermissionRequest) (*controller.GetPermissionResponse, error) {
	if req.PermissionId == "" {
		return nil, status.Error(codes.InvalidArgument, "permission_id is required")
	}

	permission, err := s.rbacManager.GetPermission(ctx, req.PermissionId)
	if err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}

	return &controller.GetPermissionResponse{
		Permission: permission,
	}, nil
}

func (s *RBACService) ListPermissions(ctx context.Context, req *controller.ListPermissionsRequest) (*controller.ListPermissionsResponse, error) {
	permissions, err := s.rbacManager.ListPermissions(ctx, req.ResourceType)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &controller.ListPermissionsResponse{
		Permissions: permissions,
	}, nil
}

// Role Management

func (s *RBACService) CreateRole(ctx context.Context, req *controller.CreateRoleRequest) (*controller.CreateRoleResponse, error) {
	if req.Role == nil {
		return nil, status.Error(codes.InvalidArgument, "role is required")
	}

	if req.Role.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "role.id is required")
	}

	err := s.rbacManager.CreateRole(ctx, req.Role)
	if err != nil {
		return nil, status.Error(codes.AlreadyExists, err.Error())
	}

	return &controller.CreateRoleResponse{
		Role: req.Role,
	}, nil
}

func (s *RBACService) GetRole(ctx context.Context, req *controller.GetRoleRequest) (*controller.GetRoleResponse, error) {
	if req.RoleId == "" {
		return nil, status.Error(codes.InvalidArgument, "role_id is required")
	}

	role, err := s.rbacManager.GetRole(ctx, req.RoleId)
	if err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}

	return &controller.GetRoleResponse{
		Role: role,
	}, nil
}

func (s *RBACService) ListRoles(ctx context.Context, req *controller.ListRolesRequest) (*controller.ListRolesResponse, error) {
	roles, err := s.rbacManager.ListRoles(ctx, req.TenantId)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &controller.ListRolesResponse{
		Roles: roles,
	}, nil
}

func (s *RBACService) UpdateRole(ctx context.Context, req *controller.UpdateRoleRequest) (*controller.UpdateRoleResponse, error) {
	if req.Role == nil {
		return nil, status.Error(codes.InvalidArgument, "role is required")
	}

	if req.Role.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "role.id is required")
	}

	err := s.rbacManager.UpdateRole(ctx, req.Role)
	if err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}

	return &controller.UpdateRoleResponse{
		Role: req.Role,
	}, nil
}

func (s *RBACService) DeleteRole(ctx context.Context, req *controller.DeleteRoleRequest) (*controller.DeleteRoleResponse, error) {
	if req.RoleId == "" {
		return nil, status.Error(codes.InvalidArgument, "role_id is required")
	}

	err := s.rbacManager.DeleteRole(ctx, req.RoleId)
	if err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}

	return &controller.DeleteRoleResponse{
		Success: true,
	}, nil
}

// Subject Management

func (s *RBACService) CreateSubject(ctx context.Context, req *controller.CreateSubjectRequest) (*controller.CreateSubjectResponse, error) {
	if req.Subject == nil {
		return nil, status.Error(codes.InvalidArgument, "subject is required")
	}

	if req.Subject.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "subject.id is required")
	}

	err := s.rbacManager.CreateSubject(ctx, req.Subject)
	if err != nil {
		return nil, status.Error(codes.AlreadyExists, err.Error())
	}

	return &controller.CreateSubjectResponse{
		Subject: req.Subject,
	}, nil
}

func (s *RBACService) GetSubject(ctx context.Context, req *controller.GetSubjectRequest) (*controller.GetSubjectResponse, error) {
	if req.SubjectId == "" {
		return nil, status.Error(codes.InvalidArgument, "subject_id is required")
	}

	subject, err := s.rbacManager.GetSubject(ctx, req.SubjectId)
	if err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}

	return &controller.GetSubjectResponse{
		Subject: subject,
	}, nil
}

func (s *RBACService) ListSubjects(ctx context.Context, req *controller.ListSubjectsRequest) (*controller.ListSubjectsResponse, error) {
	subjects, err := s.rbacManager.ListSubjects(ctx, req.TenantId, req.Type)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &controller.ListSubjectsResponse{
		Subjects: subjects,
	}, nil
}

func (s *RBACService) UpdateSubject(ctx context.Context, req *controller.UpdateSubjectRequest) (*controller.UpdateSubjectResponse, error) {
	if req.Subject == nil {
		return nil, status.Error(codes.InvalidArgument, "subject is required")
	}

	if req.Subject.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "subject.id is required")
	}

	err := s.rbacManager.UpdateSubject(ctx, req.Subject)
	if err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}

	return &controller.UpdateSubjectResponse{
		Subject: req.Subject,
	}, nil
}

func (s *RBACService) DeleteSubject(ctx context.Context, req *controller.DeleteSubjectRequest) (*controller.DeleteSubjectResponse, error) {
	if req.SubjectId == "" {
		return nil, status.Error(codes.InvalidArgument, "subject_id is required")
	}

	err := s.rbacManager.DeleteSubject(ctx, req.SubjectId)
	if err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}

	return &controller.DeleteSubjectResponse{
		Success: true,
	}, nil
}

// Role Assignment

func (s *RBACService) AssignRole(ctx context.Context, req *controller.AssignRoleRequest) (*controller.AssignRoleResponse, error) {
	if req.Assignment == nil {
		return nil, status.Error(codes.InvalidArgument, "assignment is required")
	}

	if req.Assignment.SubjectId == "" {
		return nil, status.Error(codes.InvalidArgument, "assignment.subject_id is required")
	}

	if req.Assignment.RoleId == "" {
		return nil, status.Error(codes.InvalidArgument, "assignment.role_id is required")
	}

	err := s.rbacManager.AssignRole(ctx, req.Assignment)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &controller.AssignRoleResponse{
		Assignment: req.Assignment,
	}, nil
}

func (s *RBACService) RevokeRole(ctx context.Context, req *controller.RevokeRoleRequest) (*controller.RevokeRoleResponse, error) {
	if req.SubjectId == "" {
		return nil, status.Error(codes.InvalidArgument, "subject_id is required")
	}

	if req.RoleId == "" {
		return nil, status.Error(codes.InvalidArgument, "role_id is required")
	}

	err := s.rbacManager.RevokeRole(ctx, req.SubjectId, req.RoleId, req.TenantId)
	if err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}

	return &controller.RevokeRoleResponse{
		Success: true,
	}, nil
}

func (s *RBACService) GetSubjectRoles(ctx context.Context, req *controller.GetSubjectRolesRequest) (*controller.GetSubjectRolesResponse, error) {
	if req.SubjectId == "" {
		return nil, status.Error(codes.InvalidArgument, "subject_id is required")
	}

	roles, err := s.rbacManager.GetSubjectRoles(ctx, req.SubjectId, req.TenantId)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &controller.GetSubjectRolesResponse{
		Roles: roles,
	}, nil
}

// Permission Checking

func (s *RBACService) CheckPermission(ctx context.Context, req *controller.CheckPermissionRequest) (*controller.CheckPermissionResponse, error) {
	if req.Request == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}

	if req.Request.SubjectId == "" {
		return nil, status.Error(codes.InvalidArgument, "request.subject_id is required")
	}

	if req.Request.PermissionId == "" {
		return nil, status.Error(codes.InvalidArgument, "request.permission_id is required")
	}

	response, err := s.rbacManager.CheckPermission(ctx, req.Request)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &controller.CheckPermissionResponse{
		Response: response,
	}, nil
}

func (s *RBACService) GetSubjectPermissions(ctx context.Context, req *controller.GetSubjectPermissionsRequest) (*controller.GetSubjectPermissionsResponse, error) {
	if req.SubjectId == "" {
		return nil, status.Error(codes.InvalidArgument, "subject_id is required")
	}

	permissions, err := s.rbacManager.GetSubjectPermissions(ctx, req.SubjectId, req.TenantId)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &controller.GetSubjectPermissionsResponse{
		Permissions: permissions,
	}, nil
}