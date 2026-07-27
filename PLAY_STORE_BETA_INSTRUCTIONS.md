# Publishing an Invite-Only Beta to the Google Play Store

Publishing an invite-only beta on the Google Play Store is done using the **Closed Testing** track in the Google Play Console.

### Step 1: Log into Google Play Console
1. Go to the [Google Play Console](https://play.google.com/console).
2. Log in using your `todd@keysupport.net` account. *(Note: You must have a registered Google Play Developer account).*

### Step 2: Create the App
1. From the dashboard, click **Create app**.
2. **App name:** Enter "KeySupport Validator".
3. **Default language:** Select your preferred language (e.g., English).
4. **App or Game:** Select **App**.
5. **Free or Paid:** Select **Free**.
6. Accept the Developer Program Policies and US export laws, then click **Create app**.

### Step 3: Set Up Your Invite-Only Tester List
1. On the left-hand navigation menu, scroll down to the **Testing** section and click on **Closed testing**.
2. Click the **Manage track** button next to the Alpha track (or click **Create track** if you want a custom name like "Beta 1").
3. Click on the **Testers** tab.
4. Select **Email lists** (this is how you make it invite-only).
5. Click **Create email list**, name it (e.g., "KeySupport Beta Testers"), and add the email addresses of the colleagues who will be testing the app.
6. Save the list and make sure it is checked/selected for this track.

### Step 4: Create the Release & Upload the App Bundle
1. Still in your Closed testing track, switch to the **Releases** tab and click **Create new release**.
2. **Play App Signing:** Google Play will ask to manage your app signing key. Click **Opt in** or **Continue**. *(Google will use the keystore we generated earlier as the "Upload Key" to verify it's you, and they will generate a secure distribution key on their end).*
3. Under **App bundles**, click **Upload** and select your signed `.aab` file located at:
   `app/build/outputs/bundle/release/app-release.aab`
4. **Release Details:** 
   * **Release name:** `1.0.0-beta.1`
   * **Release notes:** Add the changelog we used for GitHub.
5. Click **Next** (or **Save**).

### Step 5: Complete Initial App Declarations (Google Requirement)
Before Google lets you roll out any track, you have to complete the "App content" section.
1. Look at your left-hand menu and click **Dashboard**. You should see a section called **"Set up your app"**.
2. You will need to click through and answer short questionnaires for Privacy Policy, App Access, Ads, Content Rating, Target Audience, and Data Safety.

### Step 6: Roll Out the Release
1. Once your App Content declarations are green-checked, go back to **Testing** -> **Closed testing** -> **Manage track** -> **Releases**.
2. Click **Edit release** on your draft.
3. Click **Next** at the bottom, review any warnings, and then click **Start rollout to Closed testing**.

### Step 7: Share the Opt-In Link
1. Go to the **Testers** tab in your Closed testing track.
2. Scroll down to the **"How testers join your test"** section.
3. Click **Copy link**. 
4. Email this link to the testers on your email list!
