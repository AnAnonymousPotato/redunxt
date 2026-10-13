export interface AuthResponse {
  success: boolean;
  code: number;
  message: string;
  data?: {
    openIdConnect?: string;
  };
}

export interface DecodedToken {
  sub: string;
  username: string;
  usertype: string;
  studentid: number;
  studentprofileid: number;
  classid: number;
  sectionid: number;
  academicyearid: number;
  dbname: string;
  exp: number;
  iat: number;
}

export interface AttachmentImage {
  filename: string;
  content_type: string;
  created_on?: string;
  savefilename?: string;
  download_file_path?: string;
  cloud_front_serving_url?: string;
  servingUrl?: string;
}

export interface CircularItem {
  id: number;
  name: string;
  date: string;
  createdon?: string;
  academicyearname?: string;
  ispin?: boolean;
  discription?: string; // Note: Edunext API spells it 'discription'
  attachment?: {
    image_array?: AttachmentImage[];
  };
}

export interface MailboxItem {
  id: string;
  subject: string;
  from: string;
  employeename?: string;
  empcode?: string;
  date: string;
  message_html: string;
  status: 'Read' | 'Unread' | string;
  communicationtype?: string;
  listType?: string;
  employeename_img_path?: string;
  image_array?: AttachmentImage[];
}

export interface StudentDashboardAlert {
  title?: string;
  message?: string;
  type?: string;
}

export interface EdunextCredentials {
  userId: string;
  password?: string;
  schoolDomain: string;
  token?: string;
}

export interface HomeworkAssignment {
  id: number;
  subject: string;
  title: string;
  description: string;
  assignedBy: string;
  createdOn: string;
  deadlineDate?: string;
  deadlineTime?: string;
  submissionRequired: boolean;
  type: string;
  attachments: AttachmentImage[];
}

export interface SubjectMeta {
  id: number;
  name: string;
  code: string;
  classId: number;
  includeInCgpa: boolean;
  excludeInAttendance: boolean;
  isNegativeMarking: boolean;
  isOptional: boolean;
}

export interface SchoolNewsItem {
  id: string;
  subject: string;
  description: string;
  date: string;
  createdDateTime?: string;
  author: string;
  employeeImage?: string;
  mediaFile?: string;
  mediaUrl?: string;
}

// Attendance Types
export interface AttendanceCard {
  totalDays: number;
  presentDays?: number;
  absentDays?: number;
  leaveDays?: number;
  presentPercentage?: string;
  absentPercentage?: string;
  leavePercentage?: string;
  label?: string;
}

export interface AttendanceCalendarDay {
  date: string;
  status: 'Present' | 'Absent' | 'Leave' | 'Holiday' | string;
  color?: string;
}

export interface AttendanceData {
  overallPercentage: string;
  presentCard: AttendanceCard;
  absentCard: AttendanceCard;
  leaveCard: AttendanceCard;
  calendarList: AttendanceCalendarDay[];
  monthlyGraph: Array<{ month: string; percentage: number }>;
}

// Results Types
export interface ResultItem {
  termId: number;
  reportName: string;
  publishDate: string;
  academicYear: string;
  reportUrl: string; // Direct /mobile/schoolexamencdata URL
  fullReportUrl: string; // Absolute HTTPS link to printable CBSE report card
}

// Syllabus Types
export interface SyllabusItem {
  id: number;
  subject: string;
  fileName: string;
  description: string;
  fileUrl: string; // CloudFront CDN link
}

// Downloads / E-Resources Types
export interface DownloadItem {
  id: number;
  title: string;
  category: string;
  date: string;
  createdBy: string;
  description: string;
  fileName?: string;
  fileUrl?: string; // CloudFront CDN link
  contentType?: string;
}

// Profile & Personal Information Types
export interface StudentDetailField {
  database_label: string;
  column_label: string;
  data: string;
  isparenteditable?: boolean;
}

export interface StudentProfileData {
  studentName: string;
  admissionNo: string;
  rollNo?: string;
  className: string;
  sectionName: string;
  classTeacherName: string;
  studentType: string;
  studentImage: string;
  fatherName: string;
  motherName: string;
  studentEmail: string;
  studentMobile: string;
  studentAddress: string;
  houseName: string;
  academicYear: string;
  detailsByCategory: Record<string, StudentDetailField[]>;
}

// Account Record & Settings
export interface AccountSettings {
  avatarMode: 'edunext' | 'custom' | 'initials';
  customAvatarUrl?: string;
}

export interface AccountRecord {
  userId: string;
  schoolDomain: string;
  studentName: string;
  admissionNo: string;
  classSection: string;
  profilePhoto: string;
  settings: AccountSettings;
  lastSyncedAt?: string;
}

export interface StudentBundle {
  student: DecodedToken | null;
  profile: StudentProfileData | null;
  circulars: CircularItem[];
  mailbox: MailboxItem[];
  homework: {
    assignments: HomeworkAssignment[];
    subjects: SubjectMeta[];
  };
  news: SchoolNewsItem[];
  attendance: AttendanceData | null;
  results: ResultItem[];
  syllabus: SyllabusItem[];
  downloads: DownloadItem[];
  timestamp: string;
}
