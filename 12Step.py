import sqlite3
    
    # Admin should also be able to mark as graduated
    program.authenticate_user("admin_user", "admin123")
    try:
        student_id = program.add_student("Admin Graduation Test", "555-8888", "admingrad@example.com")
        program.record_attendance(student_id, 1, "Admin Instructor")
        program.record_attendance(student_id, 2, "Admin Instructor")
        program.mark_as_graduated(student_id)
        print("✓ Admin can mark students as graduated")
    except PermissionError as e:
        print(f"✗ Admin permission error marking as graduated: {e}")
    except Exception as e:
        print(f"✗ Error in admin graduation marking: {e}")
    
    print("\n6. Access control demonstration complete!")

def demo_user_management():
    """Demonstrate user management features"""
    program = Church12StepProgram()
    
    print("\n=== User Management Demo ===\n")
    
    # Create admin user if needed
    if not program.authenticate_user("admin_user", "admin123"):
        program.create_user("admin_user", "admin123", "admin")
    
    # Login as admin
    program.authenticate_user("admin_user", "admin123")
    
    # Show current users
    users = program.get_users()
    print("Current Users:")
    for user in users:
        print(f"  {user.username} ({user.role}) - Created: {user.created_date}")
    
    # Add new user
    new_user_created = program.create_user("new_staff", "password123", "staff")
    print(f"\nCreated new staff user: {new_user_created}")
    
    # Show updated users
    users = program.get_users()
    print("\nUpdated Users:")
    for user in users:
        print(f"  {user.username} ({user.role}) - Created: {user.created_date}")

if __name__ == "__main__":
    demo_access_control()
    demo_user_management()
