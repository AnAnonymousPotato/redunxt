import {
  AuthResponse,
  CircularItem,
  MailboxItem,
  DecodedToken,
  HomeworkAssignment,
  SubjectMeta,
  SchoolNewsItem,
  AttachmentImage,
  StudentBundle,
  AttendanceData,
  ResultItem,
  SyllabusItem,
  DownloadItem,
  StudentProfileData,
  StudentDetailField,
  AttendanceCalendarDay,
} from './types.js';

export class EdunextClient {
  private baseUrl = 'https://m1.edubac.com';
  private schoolDomain: string;
  private token: string | null = null;
  private userId: string | null = null;
  private password: string | null = null;

  constructor(schoolDomain = 'dpsharni.edunext2.com', token?: string) {
    this.schoolDomain = schoolDomain;
    if (token) {
      this.token = token;
    }
  }

  public setCredentials(userId: string, password?: string) {
    this.userId = userId;
    if (password) this.password = password;
  }

  public setToken(token: string) {
    this.token = token;
  }

  public getToken(): string | null {
    return this.token;
  }

  public getDecodedToken(): DecodedToken | null {
    if (!this.token) return null;
    try {
      const parts = this.token.split('.');
      if (parts.length !== 3) return null;
      const payload = Buffer.from(parts[1], 'base64').toString('utf-8');
      return JSON.parse(payload) as DecodedToken;
    } catch {
      return null;
    }
  }

  public isTokenExpired(): boolean {
    const decoded = this.getDecodedToken();
    if (!decoded || !decoded.exp) return true;
    const now = Math.floor(Date.now() / 1000);
    // Refresh 5 minutes before actual expiry
    return decoded.exp - 300 < now;
  }

  public async login(userId?: string, password?: string): Promise<string> {
    const uId = userId || this.userId;
    const pass = password || this.password;

    if (!uId || !pass) {
      throw new Error('User ID and Password are required to log in.');
    }

    this.userId = uId;
    this.password = pass;

    const url = `${this.baseUrl}/rest/v4/student/openconnect`;
    const headers = {
      'Content-Type': 'application/json',
      'mvcdomainurl': this.schoolDomain,
      'Connection-type': '_write',
    };

    const res = await fetch(url, {
      method: 'POST',
      headers,
      body: JSON.stringify({ userid: uId, password: pass }),
      signal: AbortSignal.timeout(15000),
    });

    if (!res.ok) {
      const errText = await res.text();
      throw new Error(`Login failed (HTTP ${res.status}): ${errText}`);
    }

    const data = (await res.json()) as AuthResponse;
    if (!data.success || !data.data?.openIdConnect) {
      throw new Error(`Login was unsuccessful: ${data.message || 'Unknown response'}`);
    }

    this.token = data.data.openIdConnect;
    return this.token;
  }

  private async ensureAuthenticated(): Promise<string> {
    if (!this.token || this.isTokenExpired()) {
      if (this.userId && this.password) {
        await this.login();
      } else {
        throw new Error('Active token is missing or expired, and no credentials were provided for auto-login.');
      }
    }
    return this.token!;
  }

  private async request<T>(endpoint: string, method: 'GET' | 'POST' = 'GET', body?: unknown): Promise<T> {
    const token = await this.ensureAuthenticated();

    const url = endpoint.startsWith('http') ? endpoint : `${this.baseUrl}${endpoint}`;
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'mvcdomainurl': this.schoolDomain,
      'Connection-type': method === 'GET' ? '_read' : '_write',
      'Authorization': `Bearer ${token}`,
    };

    const options: RequestInit = {
      method,
      headers,
      signal: AbortSignal.timeout(15000),
    };

    if (body && method !== 'GET') {
      options.body = JSON.stringify(body);
    }

    const res = await fetch(url, options);

    // If unauthorized or token expired, retry once with fresh login
    if ((res.status === 401 || res.status === 498) && this.userId && this.password) {
      this.token = null;
      await this.login();
      return this.request<T>(endpoint, method, body);
    }

    if (!res.ok) {
      const errText = await res.text();
      throw new Error(`API error (${endpoint}, HTTP ${res.status}): ${errText}`);
    }

    const json = await res.json();
    return json as T;
  }

  // 1. Circulars
  public async getCirculars(): Promise<CircularItem[]> {
    interface CircularResponse {
      success: boolean;
      data?: {
        circularlist?: CircularItem[];
      };
    }

    const res = await this.request<CircularResponse>('/rest/v4/student/getcirculardata', 'GET');
    return res.data?.circularlist || [];
  }

  // 2. Mailbox (Inbox)
  public async getMailbox(): Promise<MailboxItem[]> {
    interface MailboxResponse {
      success: boolean;
      data?: {
        list?: MailboxItem[];
        __total__?: number;
      };
    }

    const firstPage = await this.request<MailboxResponse>('/rest/v4/student/Studentinboxnew?limit=1', 'GET');
    let list = firstPage.data?.list || [];
    const total = firstPage.data?.__total__ || list.length;
    const totalPages = Math.ceil(total / 20);

    if (totalPages > 1) {
      const promises: Promise<MailboxResponse>[] = [];
      for (let p = 2; p <= totalPages; p++) {
        promises.push(this.request<MailboxResponse>(`/rest/v4/student/Studentinboxnew?limit=${p}`, 'GET'));
      }
      const pages = await Promise.all(promises);
      for (const page of pages) {
        if (page.data?.list) {
          list = list.concat(page.data.list);
        }
      }
    }

    return list;
  }

  // 3. Homework
  public async getHomework(): Promise<{ assignments: HomeworkAssignment[]; subjects: SubjectMeta[] }> {
    interface RawHomeworkResponse {
      success: boolean;
      data?: {
        assgmentData?: Array<{
          assignmentid: number;
          assignmentname: string;
          subjectname?: string;
          description?: string;
          assignBy?: string;
          cretedon?: string;
          deadlineDate?: string;
          deadlinetime?: string;
          submission_required?: boolean;
          assignmenttypesName?: string;
          attachment?: string;
        }>;
        subjectList?: Array<{
          id: number;
          name: string;
          code: string;
          classid: number;
          includeincgpa?: boolean;
          excludeinattendance?: boolean;
          isnegative_marking?: boolean;
          isoptional?: boolean;
        }>;
      };
    }

    const res = await this.request<RawHomeworkResponse>('/rest/v4/student/studentHomework', 'GET');
    const rawList = res.data?.assgmentData || [];
    const rawSubjects = res.data?.subjectList || [];

    const assignments: HomeworkAssignment[] = rawList.map((item) => {
      let atts: AttachmentImage[] = [];
      if (item.attachment) {
        try {
          const obj = typeof item.attachment === 'string' ? JSON.parse(item.attachment) : item.attachment;
          let imgArr = obj?.image_array;
          if (typeof imgArr === 'string') imgArr = JSON.parse(imgArr);
          if (Array.isArray(imgArr)) atts = imgArr as AttachmentImage[];
        } catch {}
      }

      return {
        id: item.assignmentid,
        title: item.assignmentname || 'Untitled Assignment',
        subject: item.subjectname || 'General',
        description: item.description || '',
        assignedBy: item.assignBy || 'Teacher',
        createdOn: item.cretedon || '',
        deadlineDate: item.deadlineDate || '',
        deadlineTime: item.deadlinetime || '',
        submissionRequired: Boolean(item.submission_required),
        type: item.assignmenttypesName || 'Homework',
        attachments: atts,
      };
    });

    const subjects: SubjectMeta[] = rawSubjects.map((s) => ({
      id: s.id,
      name: s.name,
      code: s.code,
      classId: s.classid,
      includeInCgpa: Boolean(s.includeincgpa),
      excludeInAttendance: Boolean(s.excludeinattendance),
      isNegativeMarking: Boolean(s.isnegative_marking),
      isOptional: Boolean(s.isoptional),
    }));

    return { assignments, subjects };
  }

  // 4. School News
  public async getSchoolNews(): Promise<SchoolNewsItem[]> {
    interface RawNewsResponse {
      success: boolean;
      data?: {
        schoolnewslist?: Array<{
          id: string;
          newssubject: string;
          newssdescription?: string;
          newsdate: string;
          creationdatetime?: string;
          employeename?: string;
          employeeimage?: string;
          filepath?: string;
          filename?: string;
        }>;
      };
    }

    const res = await this.request<RawNewsResponse>('/rest/v4/student/getstudentnews', 'GET');
    const list = res.data?.schoolnewslist || [];

    return list.map((item) => {
      let mediaUrl: string | undefined;
      if (item.filepath) {
        try {
          const parsed = typeof item.filepath === 'string' ? JSON.parse(item.filepath) : item.filepath;
          mediaUrl = parsed?.cloud_front_serving_url || parsed?.servingUrl;
        } catch {}
      }

      return {
        id: String(item.id),
        subject: item.newssubject || 'Notice',
        description: item.newssdescription || '',
        date: item.newsdate || '',
        createdDateTime: item.creationdatetime,
        author: item.employeename || 'Administration',
        mediaFile: item.filename,
        mediaUrl,
      };
    });
  }

  // 5. Attendance
  public async getAttendance(
    academicYearId?: number,
    fromDate?: string,
    toDate?: string,
    studentProfileId?: number
  ): Promise<AttendanceData> {
    const decoded = this.getDecodedToken();
    const yearId = academicYearId || decoded?.academicyearid || 21;
    const profileId = studentProfileId || decoded?.studentprofileid || 691;
    const from = fromDate || '2026-04-01';
    const to = toDate || '2027-03-31';

    interface AttendanceResponse {
      success: boolean;
      data?: {
        overallAttenndaceCard?: string;
        presentCard?: { totalDays: number; presentDays: number; presentPercentage: string; label: string };
        absentCard?: { totalDays: number; absentDays: number; absentPercentage: string; label: string };
        leaveCard?: { totalDays: number; leaveDays: number; leavePercentage: string; label: string };
        calanderattendancelist?: Record<string, Record<string, number>>;
        monthlyAttendanceGraph?: Record<string, number>;
        attendanceLeaveStatus?: Record<string, { name?: string; colorCode?: string }>;
      };
    }

    const url = `https://m2.edubac.com/rest/v4/student/getStudentAttendanceCalander?academicyearid=${yearId}&fromdate=${from}&todate=${to}&studentprofileid=${profileId}`;
    const res = await this.request<AttendanceResponse>(url, 'GET');
    const d = res.data;

    const calendarList: AttendanceCalendarDay[] = [];
    if (d?.calanderattendancelist && typeof d.calanderattendancelist === 'object') {
      const statusMap = (d.attendanceLeaveStatus || {}) as Record<string, { name?: string; colorCode?: string }>;
      for (const [monthKey, daysObj] of Object.entries(d.calanderattendancelist as Record<string, Record<string, number>>)) {
        if (typeof daysObj === 'object' && daysObj !== null) {
          for (const [dayNum, statusId] of Object.entries(daysObj)) {
            const paddedDay = dayNum.padStart(2, '0');
            const dateStr = `${monthKey}-${paddedDay}`;
            const meta = statusMap[String(statusId)];
            const statusName = meta?.name || (statusId === 1 ? 'Present' : statusId === 2 ? 'Absent' : 'Leave');
            const color = meta?.colorCode || (statusId === 1 ? '#22c55e' : statusId === 2 ? '#ef4444' : '#f59e0b');
            calendarList.push({
              date: dateStr,
              status: statusName,
              color,
            });
          }
        }
      }
    }

    const monthlyGraph: Array<{ month: string; percentage: number }> = [];
    if (d?.monthlyAttendanceGraph && typeof d.monthlyAttendanceGraph === 'object') {
      for (const [month, percentage] of Object.entries(d.monthlyAttendanceGraph as Record<string, number>)) {
        monthlyGraph.push({ month, percentage: Number(percentage) });
      }
    }

    return {
      overallPercentage: d?.overallAttenndaceCard || '0%',
      presentCard: d?.presentCard || { totalDays: 0 },
      absentCard: d?.absentCard || { totalDays: 0 },
      leaveCard: d?.leaveCard || { totalDays: 0 },
      calendarList,
      monthlyGraph,
    };
  }

  // 6. Results
  public async getResults(academicYearId?: number): Promise<ResultItem[]> {
    const decoded = this.getDecodedToken();
    const yearId = academicYearId || decoded?.academicyearid || 21;

    interface RawResultResponse {
      success: boolean;
      data?: {
        resultdata?: Array<{
          termid: number;
          reportname: string;
          publishdate: string;
          academicyearid: string;
          report: string;
        }>;
      };
    }

    const url = `https://m12.edubac.com/rest/v4/student/getResultAnalysis?acedemicYearId=${yearId}`;
    const res = await this.request<RawResultResponse>(url, 'GET');
    const list = res.data?.resultdata || [];

    return list.map((item) => ({
      termId: item.termid,
      reportName: item.reportname || 'Report Card',
      publishDate: item.publishdate || '',
      academicYear: item.academicyearid || '',
      reportUrl: item.report,
      fullReportUrl: `https://${this.schoolDomain}${item.report}`,
    }));
  }

  // 7. Syllabus
  public async getSyllabus(limit = 1): Promise<SyllabusItem[]> {
    interface RawSyllabusResponse {
      success: boolean;
      data?: {
        syllabusdata?: Array<{
          id: number;
          subjectname?: string;
          fileName?: string;
          description?: string;
          single_clound_front_url?: string;
          servingUrl?: string;
        }>;
      };
    }

    const url = `/rest/v4/student/StudentSyllabus?limit=${limit}&fts=`;
    const res = await this.request<RawSyllabusResponse>(url, 'GET');
    const list = res.data?.syllabusdata || [];

    return list.map((item) => ({
      id: item.id,
      subject: item.subjectname || 'All Subjects',
      fileName: item.fileName || '',
      description: (item.description || '').replace(/<[^>]+>/g, '').trim(),
      fileUrl: item.single_clound_front_url || item.servingUrl || '',
    }));
  }

  // 8. Downloads (E-Resources)
  public async getDownloads(limit = 1): Promise<DownloadItem[]> {
    interface RawDownloadResponse {
      success: boolean;
      data?: {
        data_array?: Array<{
          id: number;
          title1?: string;
          category1?: string;
          date1?: string;
          createdBy?: string;
          description1?: string;
          filepath?: string;
        }>;
      };
    }

    const url = `/rest/v4/student/getEresourceApi?fts=&limit=${limit}`;
    const res = await this.request<RawDownloadResponse>(url, 'GET');
    const list = res.data?.data_array || [];

    return list.map((item) => {
      let fileName = '';
      let fileUrl = '';
      let contentType = '';

      if (item.filepath) {
        try {
          const obj = typeof item.filepath === 'string' ? JSON.parse(item.filepath) : item.filepath;
          const img = obj?.image_array?.[0];
          if (img) {
            fileName = img.filename || '';
            fileUrl = img.cloud_front_serving_url || img.servingUrl || '';
            contentType = img.content_type || '';
          }
        } catch {}
      }

      return {
        id: item.id,
        title: item.title1 || 'Untitled Resource',
        category: item.category1 || 'General',
        date: item.date1 || '',
        createdBy: item.createdBy || '',
        description: item.description1 || '',
        fileName,
        fileUrl,
        contentType,
      };
    });
  }

  // 9. Profile & Personal Info
  public async getProfile(): Promise<StudentProfileData> {
    interface DetailsResponse {
      success: boolean;
      data?: {
        studentMap?: {
          studentname?: string;
          enrollmentNo?: string;
          className?: string;
          sectionName?: string;
          classTeacherName?: string;
          studenttypename?: string;
          studentImage?: string;
          fatherName?: string;
          motherName?: string;
          studentemailid?: string;
          studentmobileno?: string;
          studentaddress?: string;
          houseName?: string;
        };
        currentacademicyearName?: string;
      };
    }

    interface BasicDetailsResponse {
      success: boolean;
      data?: Record<string, StudentDetailField[]>;
    }

    const [detailsRes, basicRes] = await Promise.all([
      this.request<DetailsResponse>('https://m2.edubac.com/rest/v4/student/studentDetailsnew', 'GET'),
      this.request<BasicDetailsResponse>(
        'https://m2.edubac.com/rest/v4/student/getStudentAddEditBasicDetailsforDashbord',
        'GET'
      ),
    ]);

    const s = detailsRes.data?.studentMap;
    const basicCategories = basicRes.data || {};

    let rollNo: string | undefined;
    const schoolInfo = basicCategories['School Information'];
    if (Array.isArray(schoolInfo)) {
      const rollField = schoolInfo.find((f) => f.database_label === 'rollno');
      if (rollField) rollNo = rollField.data;
    }

    return {
      studentName: s?.studentname || 'Student',
      admissionNo: s?.enrollmentNo || '',
      rollNo,
      className: s?.className || '',
      sectionName: s?.sectionName || '',
      classTeacherName: s?.classTeacherName || '',
      studentType: s?.studenttypename || 'DAY SCHOLAR',
      studentImage: s?.studentImage || '',
      fatherName: s?.fatherName || '',
      motherName: s?.motherName || '',
      studentEmail: s?.studentemailid || '',
      studentMobile: s?.studentmobileno || '',
      studentAddress: s?.studentaddress || '',
      houseName: s?.houseName || '',
      academicYear: detailsRes.data?.currentacademicyearName || '2026-27',
      detailsByCategory: basicCategories,
    };
  }

  // Complete Student Bundle across all 9 modules
  public async getCompleteStudentBundle(): Promise<StudentBundle> {
    const [
      circResult,
      mailResult,
      hwResult,
      newsResult,
      attResult,
      resultsResult,
      syllResult,
      downResult,
      profResult,
    ] = await Promise.allSettled([
      this.getCirculars(),
      this.getMailbox(),
      this.getHomework(),
      this.getSchoolNews(),
      this.getAttendance(),
      this.getResults(),
      this.getSyllabus(),
      this.getDownloads(),
      this.getProfile(),
    ]);

    return {
      student: this.getDecodedToken(),
      profile: profResult.status === 'fulfilled' ? profResult.value : null,
      circulars: circResult.status === 'fulfilled' ? circResult.value : [],
      mailbox: mailResult.status === 'fulfilled' ? mailResult.value : [],
      homework: hwResult.status === 'fulfilled' ? hwResult.value : { assignments: [], subjects: [] },
      news: newsResult.status === 'fulfilled' ? newsResult.value : [],
      attendance: attResult.status === 'fulfilled' ? attResult.value : null,
      results: resultsResult.status === 'fulfilled' ? resultsResult.value : [],
      syllabus: syllResult.status === 'fulfilled' ? syllResult.value : [],
      downloads: downResult.status === 'fulfilled' ? downResult.value : [],
      timestamp: new Date().toISOString(),
    };
  }
}
