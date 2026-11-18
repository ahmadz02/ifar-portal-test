# IFAR Registration (online application) - setup

Folder layout (copy into your portal project):

    recruit/index.html                 IFAR dashboard (invite, review, return, send to AD)
    recruit/apply.html                 Candidate form (opened from the emailed link, no login)
    recruit/ifar-shared.js             Shared helpers
    recruit/ifar-pdf.js                PDF builder (form + compressed document pages + audit trail)
    recruit/ifar-logo.js               Logo used in the PDF
    admin/admin-ifar-applications.html Super Admin / AD page
    functions/ifar-application-email/  Supabase edge function
    sql/ifar-applications.sql          Database migration

Steps
1. Supabase SQL editor: run sql/ifar-applications.sql (needs the existing is_super_admin() function).
2. Deploy the edge function:  supabase functions deploy ifar-application-email
   Uses your existing secrets: RESEND_API_KEY, EMAIL_FROM, EMAIL_REPLY_TO, AD_EMAIL, APP_BASE_URL, SUPABASE_SERVICE_ROLE_KEY.
   Optional: RECRUIT_APP_BASE_URL (e.g. https://tsiwealth-ifar-portal.vercel.app/recruit).
   If not set, it is derived from APP_BASE_URL by replacing a trailing /coo with /recruit.
   Keep "Verify JWT" ON (the candidate page calls it with the public key).
3. Copy the files into the project as laid out above and deploy to Vercel.
4. Add a menu link to recruit/index.html in the IFAR portal index.html, and to admin/admin-ifar-applications.html in admin-dashboard.html.
