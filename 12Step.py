import sqlite3
import datetime
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from collections import defaultdict
import csv
import json
import pandas as pd
from io import StringIO
import os
import hashlib
import secrets

@dataclass
class Student:
    id: int
    name: str
    phone: str
    email: str
    graduation_date: Optional[datetime.date]
    created_date: datetime.date
    archived: bool
    archived_date: Optional[datetime.date]

@dataclass
class AttendanceRecord:
    id: int
    student_id: int
    step_number: int
    instructor: str
    date: datetime.date

@dataclass
class User:
    id: int
    username: str
    password_hash: str
    role: str  # 'admin', 'staff', 'viewer'
    created_date: datetime.date
    last_login: Optional[datetime.datetime]

class Church12StepProgram:
    def __init__(self, db_path: str = "church_program.db"):
        self.db_path = db_path
        self.init_database()
        self.current_user = None  # Track current authenticated user

    def init_database(self):
        """Initialize the database with required tables"""
        conn = sqlite3.connect(self.db_path)
        
        # Set up date handling for Python 3.12+ compatibility
        conn.execute("PRAGMA foreign_keys = ON")
        
        # Create students table with archived fields
        conn.execute('''
            CREATE TABLE IF NOT EXISTS students (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                phone TEXT,
                email TEXT,
                graduation_date DATE,
                created_date DATE DEFAULT CURRENT_DATE,
                archived BOOLEAN DEFAULT FALSE,
                archived_date DATE
            )
        ''')
        
        # Create attendance table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS attendance (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                student_id INTEGER NOT NULL,
                step_number INTEGER NOT NULL,
                instructor TEXT NOT NULL,
                date DATE NOT NULL,
                FOREIGN KEY (student_id) REFERENCES students (id)
            )
        ''')
        
        # Create users table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,  -- 'admin', 'staff', 'viewer'
                created_date DATE DEFAULT CURRENT_DATE,
                last_login DATETIME
            )
        ''')
        
        conn.commit()
        conn.close()

    def hash_password(self, password: str) -> str:
        """Hash a password using SHA-256 with salt"""
        salt = secrets.token_hex(16)
        password_with_salt = password + salt
        password_hash = hashlib.sha256(password_with_salt.encode()).hexdigest()
        return f"{salt}:{password_hash}"

    def verify_password(self, password: str, stored_hash: str) -> bool:
        """Verify a password against stored hash"""
        salt, password_hash = stored_hash.split(':')
        password_with_salt = password + salt
        computed_hash = hashlib.sha256(password_with_salt.encode()).hexdigest()
        return computed_hash == password_hash

    def create_user(self, username: str, password: str, role: str = "staff") -> bool:
        """Create a new user account"""
        if role not in ['admin', 'staff', 'viewer']:
            raise ValueError("Role must be 'admin', 'staff', or 'viewer'")
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            password_hash = self.hash_password(password)
            cursor.execute('''
                INSERT INTO users (username, password_hash, role)
                VALUES (?, ?, ?)
            ''', (username, password_hash, role))
            
            conn.commit()
            conn.close()
            return True
        except sqlite3.IntegrityError:
            conn.close()
            return False  # Username already exists

    def authenticate_user(self, username: str, password: str) -> Optional[User]:
        """Authenticate a user and return User object if successful"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, username, password_hash, role, created_date, last_login
            FROM users
            WHERE username = ?
        ''', (username,))
        
        row = cursor.fetchone()
        conn.close()
        
        if row and self.verify_password(password, row[2]):
            # Update last login
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE users 
                SET last_login = ?
                WHERE id = ?
            ''', (datetime.datetime.now(), row[0]))
            conn.commit()
            conn.close()
            
            user = User(*row)
            self.current_user = user
            return user
        return None

    def logout_user(self):
        """Logout current user"""
        self.current_user = None

    def get_current_user(self) -> Optional[User]:
        """Get the currently authenticated user"""
        return self.current_user

    def add_student(self, name: str, phone: str = "", email: str = "") -> int:
        """Add a new student to the program"""
        # Check permissions
        if not self._check_permission('add_student'):
            raise PermissionError("Insufficient permissions to add students")
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO students (name, phone, email)
            VALUES (?, ?, ?)
        ''', (name, phone, email))
        
        student_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return student_id

    def record_attendance(self, student_id: int, step_number: int, instructor: str) -> int:
        """Record attendance for a student"""
        # Check permissions
        if not self._check_permission('record_attendance'):
            raise PermissionError("Insufficient permissions to record attendance")
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO attendance (student_id, step_number, instructor, date)
            VALUES (?, ?, ?, ?)
        ''', (student_id, step_number, instructor, datetime.date.today()))
        
        attendance_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return attendance_id

    def get_student_attendance(self, student_id: int) -> List[AttendanceRecord]:
        """Get all attendance records for a student"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, student_id, step_number, instructor, date
            FROM attendance
            WHERE student_id = ?
            ORDER BY date ASC
        ''', (student_id,))
        
        records = []
        for row in cursor.fetchall():
            records.append(AttendanceRecord(*row))
        
        conn.close()
        return records

    def get_student_info(self, student_id: int) -> Optional[Student]:
        """Get student information"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, name, phone, email, graduation_date, created_date, archived, archived_date
            FROM students
            WHERE id = ?
        ''', (student_id,))
        
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return Student(*row)
        return None

    def get_all_students(self, include_archived: bool = True) -> List[Student]:
        """Get all students in the program"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        query = '''
            SELECT id, name, phone, email, graduation_date, created_date, archived, archived_date
            FROM students
        '''
        
        if not include_archived:
            query += ' WHERE archived = 0'
            
        query += ' ORDER BY name'
        
        cursor.execute(query)
        
        students = []
        for row in cursor.fetchall():
            students.append(Student(*row))
        
        conn.close()
        return students

    def get_active_students(self) -> List[Student]:
        """Get only active (non-archived) students"""
        return self.get_all_students(include_archived=False)

    def get_archived_students(self) -> List[Student]:
        """Get only archived students"""
        return self.get_all_students(include_archived=True)

    def check_graduation_eligibility(self, student_id: int) -> bool:
        """
        Check if student is eligible for graduation:
        - Attended 12 sessions in the last 15 months
        - Not previously graduated in the last 24 months
        """
        student = self.get_student_info(student_id)
        if not student:
            return False
        
        # Check if student graduated recently (within last 24 months)
        if student.graduation_date:
            time_diff = datetime.date.today() - student.graduation_date
            if time_diff.days <= 730:  # 24 months
                return False
        
        # Get attendance records from last 15 months
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        fifteen_months_ago = datetime.date.today() - datetime.timedelta(days=450)
        
        cursor.execute('''
            SELECT COUNT(*) as attendance_count
            FROM attendance
            WHERE student_id = ? AND date >= ?
        ''', (student_id, fifteen_months_ago))
        
        result = cursor.fetchone()
        conn.close()
        
        if result and result[0] >= 12:
            return True
        return False

    def get_eligible_for_graduation(self) -> List[Student]:
        """Get all students eligible for graduation"""
        students = self.get_active_students()
        eligible_students = []
        
        for student in students:
            if self.check_graduation_eligibility(student.id):
                eligible_students.append(student)
        
        return eligible_students

    def mark_as_graduated(self, student_id: int):
        """Mark a student as graduated"""
        # Check permissions
        if not self._check_permission('mark_graduated'):
            raise PermissionError("Insufficient permissions to mark students as graduated")
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE students
            SET graduation_date = ?
            WHERE id = ?
        ''', (datetime.date.today(), student_id))
        
        conn.commit()
        conn.close()

    def archive_student(self, student_id: int) -> bool:
        """
        Archive a student (move to archive status)
        This prevents them from appearing in active reports
        """
        # Check permissions
        if not self._check_permission('archive_student'):
            raise PermissionError("Insufficient permissions to archive students")
        
        student = self.get_student_info(student_id)
        if not student:
            return False
            
        if student.archived:
            return True  # Already archived
            
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE students
            SET archived = 1, archived_date = ?
            WHERE id = ?
        ''', (datetime.date.today(), student_id))
        
        conn.commit()
        conn.close()
        return True

    def unarchive_student(self, student_id: int) -> bool:
        """
        Unarchive a student (restore to active status)
        """
        # Check permissions
        if not self._check_permission('archive_student'):
            raise PermissionError("Insufficient permissions to unarchive students")
        
        student = self.get_student_info(student_id)
        if not student:
            return False
            
        if not student.archived:
            return True  # Already active
            
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE students
            SET archived = 0, archived_date = NULL
            WHERE id = ?
        ''', (student_id,))
        
        conn.commit()
        conn.close()
        return True

    def get_attendance_summary(self) -> dict:
        """Get attendance summary statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Total students
        cursor.execute('SELECT COUNT(*) FROM students')
        total_students = cursor.fetchone()[0]
        
        # Active students
        cursor.execute('SELECT COUNT(*) FROM students WHERE archived = 0')
        active_students = cursor.fetchone()[0]
        
        # Archived students
        cursor.execute('SELECT COUNT(*) FROM students WHERE archived = 1')
        archived_students = cursor.fetchone()[0]
        
        # Students with attendance in last 15 months
        fifteen_months_ago = datetime.date.today() - datetime.timedelta(days=450)
        cursor.execute('''
            SELECT COUNT(DISTINCT student_id)
            FROM attendance
            WHERE date >= ?
        ''', (fifteen_months_ago,))
        students_with_attendance = cursor.fetchone()[0]
        
        # Students eligible for graduation
        cursor.execute('''
            SELECT s.id, s.name
            FROM students s
            WHERE EXISTS (
                SELECT 1 FROM attendance a
                WHERE a.student_id = s.id
                AND a.date >= ?
                GROUP BY a.student_id
                HAVING COUNT(*) >= 12
            )
            AND (
                s.graduation_date IS NULL OR 
                s.graduation_date < ?
            )
            AND s.archived = 0
        ''', (fifteen_months_ago, datetime.date.today() - datetime.timedelta(days=730)))
        
        eligible_students = cursor.fetchall()
        
        conn.close()
        
        return {
            'total_students': total_students,
            'active_students': active_students,
            'archived_students': archived_students,
            'students_with_attendance': students_with_attendance,
            'students_eligible_for_graduation': len(eligible_students)
        }

    def get_detailed_attendance_report(self, start_date: datetime.date = None, 
                                     end_date: datetime.date = None, 
                                     include_archived: bool = True) -> List[Dict[str, Any]]:
        """Generate detailed attendance report for period"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Build query with optional date filtering
        query = '''
            SELECT s.name, s.email, s.phone, s.archived, a.step_number, a.instructor, a.date
            FROM attendance a
            JOIN students s ON a.student_id = s.id
        '''
        params = []
        
        if start_date and end_date:
            query += ' WHERE a.date BETWEEN ? AND ?'
            params.extend([start_date, end_date])
        elif start_date:
            query += ' WHERE a.date >= ?'
            params.append(start_date)
        elif end_date:
            query += ' WHERE a.date <= ?'
            params.append(end_date)
            
        # Filter by archived status if needed
        if not include_archived:
            query += ' AND s.archived = 0'
            
        query += ' ORDER BY a.date, s.name'
        
        cursor.execute(query, params)
        results = cursor.fetchall()
        conn.close()
        
        # Convert to list of dictionaries
        report_data = []
        for row in results:
            report_data.append({
                'student_name': row[0],
                'email': row[1],
                'phone': row[2],
                'archived': row[3],
                'step_number': row[4],
                'instructor': row[5],
                'date': row[6]
            })
        
        return report_data

    def get_student_progress_report(self, start_date: datetime.date = None, 
                                  end_date: datetime.date = None,
                                  include_archived: bool = True) -> List[Dict[str, Any]]:
        """Generate student progress report showing attendance by student"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        query = '''
            SELECT s.id, s.name, s.email, s.phone, s.archived,
                   COUNT(a.id) as total_sessions,
                   MAX(a.date) as last_attendance_date,
                   MIN(a.date) as first_attendance_date
            FROM students s
            LEFT JOIN attendance a ON s.id = a.student_id
        '''
        
        params = []
        if start_date and end_date:
            query += ' WHERE a.date BETWEEN ? AND ?'
            params.extend([start_date, end_date])
        elif start_date:
            query += ' WHERE a.date >= ?'
            params.append(start_date)
        elif end_date:
            query += ' WHERE a.date <= ?'
            params.append(end_date)
            
        # Filter by archived status if needed
        if not include_archived:
            query += ' AND s.archived = 0'
            
        query += ' GROUP BY s.id, s.name, s.email, s.phone, s.archived ORDER BY s.name'
        
        cursor.execute(query, params)
        results = cursor.fetchall()
        conn.close()
        
        # Convert to list of dictionaries
        report_data = []
        for row in results:
            report_data.append({
                'student_id': row[0],
                'student_name': row[1],
                'email': row[2],
                'phone': row[3],
                'archived': row[4],
                'total_sessions': row[5],
                'last_attendance_date': row[6],
                'first_attendance_date': row[7]
            })
        
        return report_data

    def get_instructor_report(self, start_date: datetime.date = None, 
                            end_date: datetime.date = None,
                            include_archived: bool = True) -> List[Dict[str, Any]]:
        """Generate instructor performance report"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        query = '''
            SELECT a.instructor, 
                   COUNT(a.id) as total_sessions,
                   COUNT(DISTINCT a.student_id) as unique_students,
                   MIN(a.date) as first_session,
                   MAX(a.date) as last_session
            FROM attendance a
        '''
        
        params = []
        if start_date and end_date:
            query += ' WHERE a.date BETWEEN ? AND ?'
            params.extend([start_date, end_date])
        elif start_date:
            query += ' WHERE a.date >= ?'
            params.append(start_date)
        elif end_date:
            query += ' WHERE a.date <= ?'
            params.append(end_date)
            
        query += ' GROUP BY a.instructor ORDER BY a.instructor'
        
        cursor.execute(query, params)
        results = cursor.fetchall()
        conn.close()
        
        # Convert to list of dictionaries
        report_data = []
        for row in results:
            report_data.append({
                'instructor': row[0],
                'total_sessions': row[1],
                'unique_students': row[2],
                'first_session_date': row[3],
                'last_session_date': row[4]
            })
        
        return report_data

    def get_graduation_eligibility_report(self, include_archived: bool = True) -> List[Dict[str, Any]]:
        """Generate report of students eligible for graduation"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get students who are eligible for graduation (12 sessions in last 15 months)
        # but haven't graduated in last 24 months
        fifteen_months_ago = datetime.date.today() - datetime.timedelta(days=450)
        twenty_four_months_ago = datetime.date.today() - datetime.timedelta(days=730)
        
        query = '''
            SELECT s.id, s.name, s.email, s.phone, 
                   COUNT(a.id) as sessions_count,
                   MAX(a.date) as last_session_date,
                   MIN(a.date) as first_session_date,
                   s.archived
            FROM students s
            JOIN attendance a ON s.id = a.student_id
            WHERE a.date >= ?
            AND s.graduation_date IS NULL OR s.graduation_date < ?
        '''
        
        params = [fifteen_months_ago, twenty_four_months_ago]
        
        if not include_archived:
            query += ' AND s.archived = 0'
            
        query += ' GROUP BY s.id, s.name, s.email, s.phone, s.archived HAVING COUNT(a.id) >= 12 ORDER BY s.name'
        
        cursor.execute(query, params)
        results = cursor.fetchall()
        conn.close()
        
        # Convert to list of dictionaries
        report_data = []
        for row in results:
            report_data.append({
                'student_id': row[0],
                'student_name': row[1],
                'email': row[2],
                'phone': row[3],
                'sessions_attended': row[4],
                'last_session_date': row[5],
                'first_session_date': row[6],
                'archived': row[7]
            })
        
        return report_data

    # Export methods
    def export_to_csv(self, report_type: str, filename: str = None, 
                     start_date: datetime.date = None, end_date: datetime.date = None,
                     include_archived: bool = True) -> str:
        """Export reports to CSV format"""
        # Check permissions for export
        if not self._check_permission('export_reports'):
            raise PermissionError("Insufficient permissions to export reports")
        
        if not filename:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"church_program_{report_type}_{timestamp}.csv"
        
        # Generate report data
        if report_type == "detailed_attendance":
            data = self.get_detailed_attendance_report(start_date, end_date, include_archived)
        elif report_type == "student_progress":
            data = self.get_student_progress_report(start_date, end_date, include_archived)
        elif report_type == "instructor_performance":
            data = self.get_instructor_report(start_date, end_date, include_archived)
        elif report_type == "graduation_eligible":
            data = self.get_graduation_eligibility_report(include_archived)
        else:
            raise ValueError(f"Unknown report type: {report_type}")
        
        # Write to CSV
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            if data:
                fieldnames = data[0].keys()
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(data)
        
        return filename

    def export_to_json(self, report_type: str, filename: str = None,
                      start_date: datetime.date = None, end_date: datetime.date = None,
                      include_archived: bool = True) -> str:
        """Export reports to JSON format"""
        # Check permissions for export
        if not self._check_permission('export_reports'):
            raise PermissionError("Insufficient permissions to export reports")
        
        if not filename:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"church_program_{report_type}_{timestamp}.json"
        
        # Generate report data
        if report_type == "detailed_attendance":
            data = self.get_detailed_attendance_report(start_date, end_date, include_archived)
        elif report_type == "student_progress":
            data = self.get_student_progress_report(start_date, end_date, include_archived)
        elif report_type == "instructor_performance":
            data = self.get_instructor_report(start_date, end_date, include_archived)
        elif report_type == "graduation_eligible":
            data = self.get_graduation_eligibility_report(include_archived)
        else:
            raise ValueError(f"Unknown report type: {report_type}")
        
        # Write to JSON
        with open(filename, 'w', encoding='utf-8') as jsonfile:
            json.dump(data, jsonfile, indent=2, default=str)
        
        return filename

    def export_to_excel(self, report_type: str, filename: str = None,
                       start_date: datetime.date = None, end_date: datetime.date = None,
                       include_archived: bool = True) -> str:
        """Export reports to Excel format"""
        # Check permissions for export
        if not self._check_permission('export_reports'):
            raise PermissionError("Insufficient permissions to export reports")
        
        if not filename:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"church_program_{report_type}_{timestamp}.xlsx"
        
        # Generate report data
        if report_type == "detailed_attendance":
            data = self.get_detailed_attendance_report(start_date, end_date, include_archived)
        elif report_type == "student_progress":
            data = self.get_student_progress_report(start_date, end_date, include_archived)
        elif report_type == "instructor_performance":
            data = self.get_instructor_report(start_date, end_date, include_archived)
        elif report_type == "graduation_eligible":
            data = self.get_graduation_eligibility_report(include_archived)
        else:
            raise ValueError(f"Unknown report type: {report_type}")
        
        # Convert to DataFrame and export to Excel
        if data:
            df = pd.DataFrame(data)
            df.to_excel(filename, index=False)
        else:
            # Create empty Excel file
            df = pd.DataFrame()
            df.to_excel(filename, index=False)
        
        return filename

    def get_report_summary(self) -> Dict[str, Any]:
        """Get a summary of all reports"""
        # Check permissions for reports
        if not self._check_permission('view_reports'):
            raise PermissionError("Insufficient permissions to view reports")
        
        summary = {
            'generated_at': datetime.datetime.now().isoformat(),
            'summary_stats': self.get_attendance_summary(),
            'report_types': [
                'detailed_attendance',
                'student_progress', 
                'instructor_performance',
                'graduation_eligible'
            ]
        }
        return summary

    def get_student_history(self, student_id: int) -> Dict[str, Any]:
        """Get complete history for a student including archived status"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, name, phone, email, graduation_date, created_date, archived, archived_date
            FROM students
            WHERE id = ?
        ''', (student_id,))
        
        student_row = cursor.fetchone()
        conn.close()
        
        if not student_row:
            return {}
        
        student = Student(*student_row)
        
        # Get attendance records
        attendance = self.get_student_attendance(student_id)
        
        return {
            'student': student,
            'attendance_records': attendance,
            'total_sessions': len(attendance),
            'last_attendance': max([a.date for a in attendance]) if attendance else None,
            'first_attendance': min([a.date for a in attendance]) if attendance else None
        }

    def find_students_to_archive(self, months_inactive: int = 24) -> List[Student]:
        """
        Find students who haven't attended any sessions in the specified number of months
        """
        # Check permissions
        if not self._check_permission('archive_student'):
            raise PermissionError("Insufficient permissions to identify students for archiving")
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Calculate the date threshold
        threshold_date = datetime.date.today() - datetime.timedelta(days=months_inactive * 30)
        
        # Find students with no attendance records after threshold date
        cursor.execute('''
            SELECT s.id, s.name, s.email, s.phone, s.graduation_date, 
                   s.created_date, s.archived, s.archived_date
            FROM students s
            WHERE s.archived = 0
            AND s.id NOT IN (
                SELECT DISTINCT student_id 
                FROM attendance 
                WHERE date >= ?
            )
            AND s.created_date < ?
            ORDER BY s.name
        ''', (threshold_date, threshold_date))
        
        results = cursor.fetchall()
        conn.close()
        
        students = []
        for row in results:
            students.append(Student(*row))
        
        return students

    def auto_archive_inactive_students(self, months_inactive: int = 24) -> Dict[str, Any]:
        """
        Automatically archive students who haven't attended sessions in the specified period
        Returns statistics about the archiving process
        """
        # Check permissions
        if not self._check_permission('archive_student'):
            raise PermissionError("Insufficient permissions to auto-archive students")
        
        students_to_archive = self.find_students_to_archive(months_inactive)
        archived_count = 0
        failed_count = 0
        skipped_count = 0
        
        for student in students_to_archive:
            try:
                if self.archive_student(student.id):
                    archived_count += 1
                else:
                    failed_count += 1
            except Exception as e:
                failed_count += 1
                print(f"Error archiving student {student.name}: {e}")
        
        return {
            'students_identified': len(students_to_archive),
            'students_archived': archived_count,
            'archiving_failed': failed_count,
            'skipped': skipped_count,
            'archived_at': datetime.datetime.now().isoformat()
        }

    def get_auto_archive_report(self, months_inactive: int = 24) -> Dict[str, Any]:
        """
        Generate a report of students who would be auto-archived
        """
        # Check permissions
        if not self._check_permission('view_reports'):
            raise PermissionError("Insufficient permissions to view archive reports")
        
        students_to_archive = self.find_students_to_archive(months_inactive)
        
        # Get detailed information about each student
        student_info_list = []
        for student in students_to_archive:
            # Get last attendance date
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                SELECT MAX(date) as last_date
                FROM attendance 
                WHERE student_id = ?
            ''', (student.id,))
            result = cursor.fetchone()
            conn.close()
            
            last_attendance = result[0] if result and result[0] else "Never"
            
            student_info_list.append({
                'student_id': student.id,
                'student_name': student.name,
                'email': student.email,
                'phone': student.phone,
                'last_attendance_date': last_attendance,
                'days_since_last_attendance': None  # Will calculate this
            })
        
        # Calculate days since last attendance for those who have attended
        for info in student_info_list:
            if info['last_attendance_date'] != "Never":
                try:
                    last_date = datetime.datetime.strptime(info['last_attendance_date'], '%Y-%m-%d').date()
                    days_since = (datetime.date.today() - last_date).days
                    info['days_since_last_attendance'] = days_since
                except:
                    info['days_since_last_attendance'] = 'Unknown'
        
        return {
            'generated_at': datetime.datetime.now().isoformat(),
            'months_inactive_threshold': months_inactive,
            'students_to_archive': len(student_info_list),
            'students_info': student_info_list
        }

    def _check_permission(self, permission: str) -> bool:
        """Check if current user has the required permission"""
        if not self.current_user:
            return False
            
        user_role = self.current_user.role
        
        # Define permission levels
        permissions = {
            'admin': ['add_student', 'record_attendance', 'mark_graduated', 
                     'archive_student', 'export_reports', 'view_reports'],
            'staff': ['add_student', 'record_attendance', 'mark_graduated', 'export_reports', 'view_reports'],
            'viewer': ['export_reports', 'view_reports']
        }
        
        # If user role has the permission, allow access
        return permission in permissions.get(user_role, [])

    def get_users(self) -> List[User]:
        """Get all users (Admin only)"""
        if not self.current_user or self.current_user.role != 'admin':
            raise PermissionError("Insufficient permissions to view users")
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, username, password_hash, role, created_date, last_login
            FROM users
            ORDER BY username
        ''')
        
        users = []
        for row in cursor.fetchall():
            users.append(User(*row))
        
        conn.close()
        return users

    def delete_user(self, user_id: int) -> bool:
        """Delete a user (Admin only)"""
        if not self.current_user or self.current_user.role != 'admin':
            raise PermissionError("Insufficient permissions to delete users")
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
            conn.commit()
            conn.close()
            return True
        except:
            conn.close()
            return False

def demo_access_control():
    """Demonstrate the access control functionality"""
    # Create program instance
    program = Church12StepProgram()
    
    print("=== Church 12 Step Program - Access Control Demo ===\n")
    
    # Create users with different roles
    print("1. Creating user accounts...")
    
    # Create admin user
    admin_created = program.create_user("admin_user", "admin123", "admin")
    print(f"Admin user created: {admin_created}")
    
    # Create staff user
    staff_created = program.create_user("staff_user", "staff123", "staff")
    print(f"Staff user created: {staff_created}")
    
    # Create viewer user
    viewer_created = program.create_user("viewer_user", "viewer123", "viewer")
    print(f"Viewer user created: {viewer_created}")
    
    # Test authentication
    print("\n2. Testing authentication...")
    
    # Test admin login
    admin_user = program.authenticate_user("admin_user", "admin123")
    if admin_user:
        print(f"✓ Admin login successful: {admin_user.username} (Role: {admin_user.role})")
    else:
        print("✗ Admin login failed")
    
    # Test staff login
    program.logout_user()  # Logout first
    staff_user = program.authenticate_user("staff_user", "staff123")
    if staff_user:
        print(f"✓ Staff login successful: {staff_user.username} (Role: {staff_user.role})")
    else:
        print("✗ Staff login failed")
    
    # Test viewer login
    program.logout_user()  # Logout first
    viewer_user = program.authenticate_user("viewer_user", "viewer123")
    if viewer_user:
        print(f"✓ Viewer login successful: {viewer_user.username} (Role: {viewer_user.role})")
    else:
        print("✗ Viewer login failed")
    
    # Demonstrate permissions for each role
    print("\n3. Testing permission levels...")
    
    # Test admin permissions
    program.logout_user()
    program.authenticate_user("admin_user", "admin123")
    
    try:
        student_id = program.add_student("Test Admin Student", "555-0000", "admin@example.com")
        print("✓ Admin can add students")
    except PermissionError as e:
        print(f"✗ Admin permission error: {e}")
    
    try:
        program.record_attendance(student_id, 1, "Admin Instructor")
        print("✓ Admin can record attendance")
    except PermissionError as e:
        print(f"✗ Admin permission error: {e}")
    
    try:
        program.mark_as_graduated(student_id)
        print("✓ Admin can mark students as graduated")
    except PermissionError as e:
        print(f"✗ Admin permission error: {e}")
    
    # Test staff permissions
    program.logout_user()
    program.authenticate_user("staff_user", "staff123")
    
    try:
        student_id = program.add_student("Test Staff Student", "555-1111", "staff@example.com")
        print("✓ Staff can add students")
    except PermissionError as e:
        print(f"✗ Staff permission error: {e}")
    
    try:
        program.record_attendance(student_id, 1, "Staff Instructor")
        print("✓ Staff can record attendance")
    except PermissionError as e:
        print(f"✗ Staff permission error: {e}")
    
    try:
        program.mark_as_graduated(student_id)
        print("✓ Staff can mark students as graduated")
    except PermissionError as e:
        print(f"✗ Staff permission error: {e}")
    
    try:
        program.export_to_csv("student_progress", "staff_export.csv")
        print("✓ Staff can export reports")
    except PermissionError as e:
        print(f"✗ Staff export permission error: {e}")
    
    # Test viewer permissions
    program.logout_user()
    program.authenticate_user("viewer_user", "viewer123")
    
    try:
        program.export_to_csv("student_progress", "viewer_export.csv")
        print("✓ Viewer can export reports")
    except PermissionError as e:
        print(f"✗ Viewer permission error: {e}")
    
    # Show that viewer cannot add students
    try:
        student_id = program.add_student("Test Viewer Student", "555-2222", "viewer@example.com")
        print("✓ Viewer can add students (unexpected)")
    except PermissionError as e:
        print(f"✓ Viewer correctly denied adding students: {e}")
    
    # Test permissions for archive functionality
    print("\n4. Testing archive functionality permissions...")
    program.logout_user()
    program.authenticate_user("admin_user", "admin123")
    
    try:
        result = program.auto_archive_inactive_students(24)
        print(f"✓ Admin can auto-archive: {result['students_archived']} students archived")
    except PermissionError as e:
        print(f"✗ Admin archive permission error: {e}")
    
    program.logout_user()
    program.authenticate_user("staff_user", "staff123")
    
    try:
        result = program.auto_archive_inactive_students(24)
        print(f"✗ Staff incorrectly allowed to auto-archive: {result['students_archived']} students archived")
    except PermissionError as e:
        print(f"✓ Staff correctly denied auto-archive: {e}")
    
    # Demonstrate graduation marking specifically
    print("\n5. Testing graduation marking permissions...")
    program.logout_user()
    
    # Staff should be able to mark as graduated
    program.authenticate_user("staff_user", "staff123")
    try:
        student_id = program.add_student("Graduation Test Student", "555-9999", "grad@example.com")
        program.record_attendance(student_id, 1, "Staff Instructor")
        program.record_attendance(student_id, 2, "Staff Instructor")
        program.record_attendance(student_id, 3, "Staff Instructor")
        program.record_attendance(student_id, 4, "Staff Instructor")
        program.record_attendance(student_id, 5, "Staff Instructor")
        program.record_attendance(student_id, 6, "Staff Instructor")
        program.record_attendance(student_id, 7, "Staff Instructor")
        program.record_attendance(student_id, 8, "Staff Instructor")
        program.record_attendance(student_id, 9, "Staff Instructor")
        program.record_attendance(student_id, 10, "Staff Instructor")
        program.record_attendance(student_id, 11, "Staff Instructor")
        program.record_attendance(student_id, 12, "Staff Instructor")
        program.mark_as_graduated(student_id)
        print("✓ Staff can mark students as graduated")
    except PermissionError as e:
        print(f"✗ Staff permission error marking as graduated: {e}")
    except Exception as e:
        print(f"✗ Error in graduation marking: {e}")
    
    program.logout_user()
    
    # Admin should also be able to mark as graduated
    program.authenticate_user("admin_user", "admin123")
    try:
        student_id = program.add_student("Admin Graduation Test", "555-8888", "admingrad
