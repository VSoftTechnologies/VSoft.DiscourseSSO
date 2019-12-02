## VSoft.DiscourseSSO

This a module for Dotnetnuke (9.4.1) that enables single signon from Discourse forums.

### Installation

#### DNN

Install the module like you would any other extension in dotnet nuke.

Add a new page /ssoauth

Add the module to the page (in any pane) and remove any other modules from the page (ie the default html module).

In the page settings, set the permissions so that it is visible to Registered Users.

In your DNN web.config add the following :

```xml
    <appSettings>
        <add key="ssoSecret" value="your sso secret from the discourse settings" />
        <add key="ssoDiscourseUrl" value="https://yourforums/" />
        ...
```

In the DNN SEO settings , add the following to the "Do Not Redirect URL Regular Expression" setting.

`|/ssoauth`

**Do not skip this step**, otherwise the dnn friendly url rewriter will rewrite the query parameters as path segments and the module will not work. Also do not change the page name, the module will not work correctly if the page name is different (I have no idea why, mvc modules in dnn are kinda flakey).

If you visit the page in a browser you will just see "nothing to see here" - if you do not see that the module is not loading.

##### DNN Roles

Add a role to your DNN installation called "ForumsAdmin" - and add this role to your DNN users who will need admin access to discourse - **do not skip this step**, otherwise you will be locked out of administering your discourse instance!

Add a role called "ForumsModerator" - for users who will need moderator permissions on discourse.

#### Discourse

Backup your discourse instance before enabling SSO, and review this topic

https://meta.discourse.org/t/official-single-sign-on-for-discourse-sso/13045

for info on how to disable SSO **BEFORE** you enable SSO on your discourse instance. Note that once SSO is enabled in discourse, you cannot use the existing discourse users (they will still be there if turn off sso later).

In your Discourse settings, enable SSO and set the sso url to

`https://www.yourdotnetnukesite/ssoauth`

and set the SSO secret to the same value as the dnn web config.

Once SSO is enabled in discourse, the login button will redirect you to the /ssoauth page on your site, which in turn will redirect to the login page. Once logged in, you will be redirected back to your discourse instance. If you were already logged in to the the dnn site you will not see the dnn login page.

I recommend you set this all up in a test enviornment first (test dnn and discourse instances) to make sure you understand how this works before inflicting it on your production environment.
