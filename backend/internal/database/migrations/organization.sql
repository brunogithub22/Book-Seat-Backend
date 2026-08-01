Create TABLE organization{
    name_organization VARCHAR(255) NOT NULL,
    admin_id UUID NOT NULL REFERENCES person(id),
    role_name JSONB NOT NULL DEFAULT '{}'::jsonb
}