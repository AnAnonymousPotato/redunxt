export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin') || '';
    const isAllowedOrigin = !origin || 
      origin.includes('vercel.app') || 
      origin.includes('localhost') || 
      origin.includes('127.0.0.1');

    const corsHeaders = {
      'Access-Control-Allow-Origin': isAllowedOrigin ? (origin || '*') : 'https://redunxt.vercel.app',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, x-school-domain, x-user-id, x-device-token',
      'Access-Control-Max-Age': '86400',
    };

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    const url = new URL(request.url);

    // 1. Health check
    if (url.pathname === '/ping') {
      return new Response(JSON.stringify({ ok: true, status: 'active', secure: true }), {
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    // 2. POST /accounts/login - Validate with Edunext and register secure device session
    if (url.pathname === '/accounts/login' && request.method === 'POST') {
      try {
        const { userId, password, schoolDomain = 'dpsharni.edunext2.com' } = await request.json();
        const uId = String(userId || '').trim();
        const pass = String(password || '').trim();

        if (!uId || !pass) {
          return new Response(JSON.stringify({ success: false, error: 'User ID and password are required.' }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' },
          });
        }

        // Authenticate directly against Edunext REST endpoint
        const loginRes = await fetch('https://m1.edubac.com/rest/v4/student/openconnect', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'mvcdomainurl': schoolDomain,
            'Connection-type': '_write'
          },
          body: JSON.stringify({ userid: uId, password: pass })
        });
        const loginData = await loginRes.json();

        if (!loginData.success || !loginData.data?.openIdConnect) {
          return new Response(JSON.stringify({
            success: false,
            error: loginData.message || 'Invalid User ID or Password from Edunext.'
          }), {
            status: 401,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' },
          });
        }

        const token = loginData.data.openIdConnect;

        // Fetch basic profile info
        let studentName = 'Student';
        let admissionNo = '';
        let classSection = '';
        let profilePhoto = '';

        try {
          const profRes = await fetch('https://m1.edubac.com/rest/v4/student/getStudentPersonalDetail', {
            headers: {
              'Authorization': 'Bearer ' + token,
              'mvcdomainurl': schoolDomain,
              'Connection-type': '_read'
            }
          });
          const profData = await profRes.json();
          if (profData.success && profData.data?.personalDetail) {
            const p = profData.data.personalDetail;
            studentName = p.student_name || studentName;
            admissionNo = p.admission_no || admissionNo;
            classSection = p.class_name ? (p.class_name + (p.section_name ? '-' + p.section_name : '')) : '';
            profilePhoto = p.student_photo || '';
          }
        } catch {}

        // Decode token expiration
        let tokenExpiry = 0;
        try {
          const parts = token.split('.');
          const payload = JSON.parse(atob(parts[1]));
          tokenExpiry = payload.exp || 0;
        } catch {}

        // Parameterized upsert into D1 accounts table (SQL injection impossible)
        await env.DB.prepare("INSERT INTO accounts (user_id, password, school_domain, student_name, admission_no, class_section, profile_photo, cached_token, token_expires_at, last_synced_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP) ON CONFLICT(user_id) DO UPDATE SET password = excluded.password, school_domain = excluded.school_domain, student_name = excluded.student_name, admission_no = excluded.admission_no, class_section = excluded.class_section, profile_photo = excluded.profile_photo, cached_token = excluded.cached_token, token_expires_at = excluded.token_expires_at, last_synced_at = excluded.last_synced_at, updated_at = CURRENT_TIMESTAMP").bind(
          uId,
          pass,
          schoolDomain,
          studentName,
          admissionNo,
          classSection,
          profilePhoto,
          token,
          tokenExpiry
        ).run();

        // Generate cryptographically secure random device token for this authorized device
        const deviceToken = crypto.randomUUID().replace(/-/g, '') + crypto.randomUUID().replace(/-/g, '');
        const userAgent = request.headers.get('User-Agent') || 'browser';

        await env.DB.prepare("INSERT INTO device_sessions (user_id, device_token, user_agent, created_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)").bind(uId, deviceToken, userAgent).run();

        // Fetch avatar settings
        const existing = await env.DB.prepare(
          'SELECT avatar_mode, custom_avatar_url FROM accounts WHERE user_id = ?'
        ).bind(uId).first();

        // Strictly omit password from the response
        return new Response(JSON.stringify({
          success: true,
          token,
          deviceToken,
          account: {
            userId: uId,
            studentName,
            admissionNo,
            classSection,
            profilePhoto,
            avatarMode: existing?.avatar_mode || 'edunext',
            customAvatarUrl: existing?.custom_avatar_url || null,
            schoolDomain
          }
        }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      } catch (err) {
        return new Response(JSON.stringify({ success: false, error: err.message }), {
          status: 500,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }
    }

    // 3. POST /accounts/auto-login - Silent background token refresh for THIS authorized device only
    if (url.pathname === '/accounts/auto-login' && request.method === 'POST') {
      try {
        const { userId, deviceToken } = await request.json();
        const uId = String(userId || '').trim();
        const dToken = String(deviceToken || '').trim();

        if (!uId) {
          return new Response(JSON.stringify({ success: false, error: 'User ID is required.' }), {
            status: 400,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' },
          });
        }

        // Verify that this device has an authorized device_session
        if (!dToken) {
          return new Response(JSON.stringify({
            success: false,
            error: 'Missing device authorization token. Please log in with credentials.'
          }), {
            status: 401,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' },
          });
        }

        const validSession = await env.DB.prepare(
          'SELECT id FROM device_sessions WHERE user_id = ? AND device_token = ?'
        ).bind(uId, dToken).first();

        if (!validSession) {
          return new Response(JSON.stringify({
            success: false,
            error: 'Unauthorized or expired device session. Please enter credentials to sign in.'
          }), {
            status: 401,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' },
          });
        }

        // Query ONLY the requesting account
        const account = await env.DB.prepare(
          'SELECT * FROM accounts WHERE user_id = ?'
        ).bind(uId).first();

        if (!account) {
          return new Response(JSON.stringify({ success: false, error: 'No stored credentials found. Please sign in again.' }), {
            status: 404,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' },
          });
        }

        let token = account.cached_token;
        const now = Math.floor(Date.now() / 1000);
        const isExpired = !account.token_expires_at || account.token_expires_at - 300 < now;

        // If expired or missing, auto-authenticate against Edunext using securely stored password
        if (isExpired || !token) {
          const loginRes = await fetch('https://m1.edubac.com/rest/v4/student/openconnect', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'mvcdomainurl': account.school_domain || 'dpsharni.edunext2.com',
              'Connection-type': '_write'
            },
            body: JSON.stringify({ userid: account.user_id, password: account.password })
          });
          const loginData = await loginRes.json();

          if (!loginData.success || !loginData.data?.openIdConnect) {
            return new Response(JSON.stringify({
              success: false,
              error: 'Session refresh failed: ' + (loginData.message || 'Password may have changed.')
            }), {
              status: 401,
              headers: { ...corsHeaders, 'Content-Type': 'application/json' },
            });
          }
          token = loginData.data.openIdConnect;

          let newExp = 0;
          try {
            const parts = token.split('.');
            newExp = JSON.parse(atob(parts[1])).exp || 0;
          } catch {}

          await env.DB.prepare(
            'UPDATE accounts SET cached_token = ?, token_expires_at = ?, last_synced_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?'
          ).bind(token, newExp, account.user_id).run();
        }

        // Return token and profile without password
        return new Response(JSON.stringify({
          success: true,
          token,
          account: {
            userId: account.user_id,
            studentName: account.student_name,
            admissionNo: account.admission_no,
            classSection: account.class_section,
            profilePhoto: account.profile_photo,
            avatarMode: account.avatar_mode || 'edunext',
            customAvatarUrl: account.custom_avatar_url,
            schoolDomain: account.school_domain
          }
        }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      } catch (err) {
        return new Response(JSON.stringify({ success: false, error: err.message }), {
          status: 500,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }
    }

    // 4. POST /accounts/logout - Invalidate THIS device session in D1
    if (url.pathname === '/accounts/logout' && request.method === 'POST') {
      try {
        const { userId, deviceToken } = await request.json();
        const uId = String(userId || '').trim();
        const dToken = String(deviceToken || '').trim();

        if (uId && dToken) {
          await env.DB.prepare(
            'DELETE FROM device_sessions WHERE user_id = ? AND device_token = ?'
          ).bind(uId, dToken).run();
        }

        return new Response(JSON.stringify({ success: true, message: 'Device session revoked.' }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      } catch (err) {
        return new Response(JSON.stringify({ success: false, error: err.message }), {
          status: 500,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }
    }

    // 5. POST /accounts/settings - Update profile picture preferences for THIS account
    if (url.pathname === '/accounts/settings' && request.method === 'POST') {
      try {
        const { userId, deviceToken, avatarMode, customAvatarUrl } = await request.json();
        const uId = String(userId || '').trim();
        const dToken = String(deviceToken || '').trim();

        if (!uId || !dToken) {
          return new Response(JSON.stringify({ success: false, error: 'Authentication required.' }), {
            status: 401,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' },
          });
        }

        const validSession = await env.DB.prepare(
          'SELECT id FROM device_sessions WHERE user_id = ? AND device_token = ?'
        ).bind(uId, dToken).first();

        if (!validSession) {
          return new Response(JSON.stringify({ success: false, error: 'Unauthorized device.' }), {
            status: 401,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' },
          });
        }

        await env.DB.prepare(
          'UPDATE accounts SET avatar_mode = ?, custom_avatar_url = ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?'
        ).bind(avatarMode || 'edunext', customAvatarUrl || null, uId).run();

        return new Response(JSON.stringify({ success: true, message: 'Settings saved.' }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      } catch (err) {
        return new Response(JSON.stringify({ success: false, error: err.message }), {
          status: 500,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }
    }

    // 6. GET/POST /data - Concurrently fetch all 9 modules directly from Edunext microservices
    if (url.pathname === '/data') {
      const authHeader = request.headers.get('Authorization') || '';
      let token = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : null;
      const schoolDomain = request.headers.get('x-school-domain') || 'dpsharni.edunext2.com';

      if (!token) {
        return new Response(JSON.stringify({ success: false, error: 'Authorization token required.' }), {
          status: 401,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }

      const headers = {
        'Authorization': 'Bearer ' + token,
        'mvcdomainurl': schoolDomain,
        'Connection-type': '_read',
        'Content-Type': 'application/json'
      };

      try {
        let yearId = 21;
        let profileId = 691;
        try {
          const parts = token.split('.');
          const payload = JSON.parse(atob(parts[1]));
          if (payload.academicyearid) yearId = payload.academicyearid;
          if (payload.studentprofileid) profileId = payload.studentprofileid;
        } catch {}

        const attUrl = 'https://m2.edubac.com/rest/v4/student/getStudentAttendanceCalander?academicyearid=' + yearId + '&fromdate=2026-04-01&todate=2027-03-31&studentprofileid=' + profileId;
        const resUrl = 'https://m12.edubac.com/rest/v4/student/getResultAnalysis?acedemicYearId=' + yearId;

        const [
          circularsRes,
          mailboxRes,
          newsRes,
          profileRes,
          homeworkRes,
          resultsRes,
          syllabusRes,
          downloadsRes,
          attendanceRes
        ] = await Promise.all([
          fetch('https://m1.edubac.com/rest/v4/student/getCircularList', { method: 'POST', headers, body: JSON.stringify({ page: 1, limit: 100 }) }).catch(() => null),
          fetch('https://m1.edubac.com/rest/v4/student/getMailBoxList', { method: 'POST', headers, body: JSON.stringify({ page: 1, limit: 100, is_inbox: '1' }) }).catch(() => null),
          fetch('https://m1.edubac.com/rest/v4/student/getNewsList', { method: 'POST', headers, body: JSON.stringify({ page: 1, limit: 50 }) }).catch(() => null),
          fetch('https://m1.edubac.com/rest/v4/student/getStudentPersonalDetail', { method: 'POST', headers, body: JSON.stringify({}) }).catch(() => null),
          fetch('https://m1.edubac.com/rest/v4/student/getHomeworkList', { method: 'POST', headers, body: JSON.stringify({ page: 1, limit: 100 }) }).catch(() => null),
          fetch(resUrl, { method: 'GET', headers }).catch(() => null),
          fetch('https://m1.edubac.com/rest/v4/student/getSyllabusList', { method: 'POST', headers, body: JSON.stringify({ page: 1, limit: 100 }) }).catch(() => null),
          fetch('https://m1.edubac.com/rest/v4/student/getDownloadMasterList', { method: 'POST', headers, body: JSON.stringify({ page: 1, limit: 100 }) }).catch(() => null),
          fetch(attUrl, { method: 'GET', headers }).catch(() => null)
        ]);

        const [circulars, mailbox, news, profile, homework, results, syllabus, downloads, attendance] = await Promise.all([
          circularsRes ? circularsRes.json().catch(() => ({})) : {},
          mailboxRes ? mailboxRes.json().catch(() => ({})) : {},
          newsRes ? newsRes.json().catch(() => ({})) : {},
          profileRes ? profileRes.json().catch(() => ({})) : {},
          homeworkRes ? homeworkRes.json().catch(() => ({})) : {},
          resultsRes ? resultsRes.json().catch(() => ({})) : {},
          syllabusRes ? syllabusRes.json().catch(() => ({})) : {},
          downloadsRes ? downloadsRes.json().catch(() => ({})) : {},
          attendanceRes ? attendanceRes.json().catch(() => ({})) : {}
        ]);

        // Safe extraction and normalization
        const rawResults = results?.data?.resultdata || results?.data?.results || results?.resultdata || (Array.isArray(results?.data) ? results?.data : (Array.isArray(results) ? results : []));
        const normalizedResults = Array.isArray(rawResults) ? rawResults.map(r => ({
          termId: r.termid || r.termId,
          reportName: r.reportname || r.reportName || "Report Card",
          reportname: r.reportname || r.reportName || "Report Card",
          publishDate: r.publishdate || r.publishDate || "",
          publishdate: r.publishdate || r.publishDate || "",
          academicYear: r.academicyearid || r.academicYear || "",
          reportUrl: r.report || r.reportUrl || "",
          report: r.report || r.reportUrl || "",
          fullReportUrl: (r.report || r.reportUrl || "").startsWith("http") ? (r.report || r.reportUrl) : ("https://" + schoolDomain + (r.report || r.reportUrl || ""))
        })) : [];

        const rawHwList = homework?.data?.assgmentData || homework?.data?.homework_list || homework?.data?.assignments || (Array.isArray(homework?.data) ? homework?.data : (Array.isArray(homework) ? homework : []));
        const rawSubjects = homework?.data?.subjectList || homework?.data?.subjects || [];
        const normalizedHomework = {
          assignments: Array.isArray(rawHwList) ? rawHwList.map(a => {
            let atts = [];
            if (a.attachment) {
              try {
                const obj = typeof a.attachment === "string" ? JSON.parse(a.attachment) : a.attachment;
                let imgArr = obj?.image_array;
                if (typeof imgArr === "string") imgArr = JSON.parse(imgArr);
                if (Array.isArray(imgArr)) atts = imgArr;
              } catch {}
            } else if (Array.isArray(a.attachments)) {
              atts = a.attachments;
            }
            return {
              id: a.assignmentid || a.id,
              title: a.assignmentname || a.title || "Assignment",
              subject: a.subjectname || a.subject || "General",
              description: a.description || "",
              assignedBy: a.assignBy || a.assignedBy || "Teacher",
              createdOn: a.cretedon || a.createdOn || "",
              deadlineDate: a.deadlineDate || a.deadlinedate || "",
              deadlineTime: a.deadlinetime || a.deadlineTime || "",
              submissionRequired: Boolean(a.submission_required || a.submissionRequired),
              type: a.assignmenttypesName || a.type || "Homework",
              attachments: atts
            };
          }) : [],
          subjects: Array.isArray(rawSubjects) ? rawSubjects : []
        };

        const attData = attendance?.data || attendance || {};
        const monthlyGraph = [];
        if (attData.monthlyAttendanceGraph && typeof attData.monthlyAttendanceGraph === "object") {
          for (const [month, percentage] of Object.entries(attData.monthlyAttendanceGraph)) {
            monthlyGraph.push({ month, percentage: Number(percentage) });
          }
        } else if (Array.isArray(attData.monthlyGraph)) {
          monthlyGraph.push(...attData.monthlyGraph);
        }

        const calendarList = [];
        if (attData.calanderattendancelist && typeof attData.calanderattendancelist === "object") {
          const statusMap = attData.attendanceLeaveStatus || {};
          for (const [monthKey, daysObj] of Object.entries(attData.calanderattendancelist)) {
            if (typeof daysObj === "object" && daysObj !== null) {
              for (const [dayNum, statusId] of Object.entries(daysObj)) {
                const paddedDay = String(dayNum).padStart(2, "0");
                const dateStr = monthKey + "-" + paddedDay;
                const meta = statusMap[String(statusId)];
                const statusName = meta?.name || (statusId === 1 ? "Present" : statusId === 2 ? "Absent" : "Leave");
                const color = meta?.colorCode || (statusId === 1 ? "#22c55e" : statusId === 2 ? "#ef4444" : "#f59e0b");
                calendarList.push({ date: dateStr, status: statusName, statusId: Number(statusId), color });
              }
            }
          }
        } else if (Array.isArray(attData.calendarList)) {
          calendarList.push(...attData.calendarList);
        }

        const normalizedAttendance = {
          overallPercentage: attData.overallAttenndaceCard || attData.overallPercentage || "0%",
          presentCard: attData.presentCard || { totalDays: 0, presentDays: 0, presentPercentage: "0%" },
          absentCard: attData.absentCard || { totalDays: 0, absentDays: 0, absentPercentage: "0%" },
          leaveCard: attData.leaveCard || { totalDays: 0, leaveDays: 0, leavePercentage: "0%" },
          calendarList,
          monthlyGraph
        };

        const normalizedCirculars = circulars?.data?.circular_list || circulars?.data?.circularlist || (Array.isArray(circulars?.data) ? circulars?.data : (Array.isArray(circulars) ? circulars : []));
        const normalizedMailbox = mailbox?.data?.mail_box_list || mailbox?.data?.list || (Array.isArray(mailbox?.data) ? mailbox?.data : (Array.isArray(mailbox) ? mailbox : []));
        const normalizedNews = news?.data?.news_list || news?.data?.schoolnewslist || (Array.isArray(news?.data) ? news?.data : (Array.isArray(news) ? news : []));
        const normalizedSyllabus = syllabus?.data?.syllabus_list || syllabus?.data?.list || (Array.isArray(syllabus?.data) ? syllabus?.data : (Array.isArray(syllabus) ? syllabus : []));
        const normalizedDownloads = downloads?.data?.download_list || downloads?.data?.list || (Array.isArray(downloads?.data) ? downloads?.data : (Array.isArray(downloads) ? downloads : []));
        const normalizedProfile = profile?.data?.personalDetail || profile?.data?.studentDetails || profile?.data || null;

        return new Response(JSON.stringify({
          success: true,
          circulars: normalizedCirculars,
          mailbox: normalizedMailbox,
          news: normalizedNews,
          profile: normalizedProfile,
          homework: normalizedHomework,
          results: normalizedResults,
          syllabus: normalizedSyllabus,
          downloads: normalizedDownloads,
          attendance: normalizedAttendance
        }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      } catch (err) {
        return new Response(JSON.stringify({ success: false, error: err.message }), {
          status: 500,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }
    }

    return new Response('Not Found', { status: 404, headers: corsHeaders });
  }
};
