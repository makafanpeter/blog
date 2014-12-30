#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import os
import re
from string import letters
import random
import string
import hashlib
import hmac
import logging
import time

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)



class BaseHandler(webapp2.RequestHandler):
    def render(self, template, **kw):
        self.response.out.write(self.render_str(template, **kw))

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self,template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)


class Blog(db.Model):
    title = db.StringProperty(required = True)
    body = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)


class User(db.Model):
    username = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    email = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    
        

class MainHandler(BaseHandler):
    def get(self):
        val = self.request.cookies.get('name','hacked')
        username = check_secure_val(val)
        if username:
            posts = db.GqlQuery("select * from Blog order by created desc limit 10")
            self.render("index.html",posts=posts)
        else:
            self.redirect('/blog/signup')
        


class NewPost(BaseHandler):
    def get(self):
        self.render("newpost.html")

    def post(self):
        title = self.request.get("subject")
        body = self.request.get("content")
        if title and body:
            blog = Blog(title=title,body=body)
            blog.put()
            id = blog.key().id()
            self.redirect("/blog/%d"%id)
        else:
            error = "Please provide a title and body fo blog entry"
            self.render("newpost.html",title=title,body=body,error=error)


class Permalink(BaseHandler):
    def get(self,blog_id):
        s = Blog.get_by_id(int(blog_id))
        if s is None:
            self.response.set_status(404) 
            self.render("404.html")
        else:
            self.render("post.html", posts=[s])


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

def make_salt():
    return ''.join(random.sample(string.letters,5)) 

def make_pw_hash(name, pw, salt = ''):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (h, salt)

def valid_pw(name, pw, h):
    hashed_s = h.split(',')[1]
    return h == make_salt(name, pw, hashed_s)

SECRET = 'qwerty1234'
def hash_str(s):
    return hmac.new(SECRET,s).hexdigest()

def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val
    


class Signup(BaseHandler):

    def get(self):
        self.render("signup.html")

    def post(self):
        have_error = False
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        params = dict(username = username,
                      email = email)

        if not valid_username(username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif password != verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup.html', **params)
        else:
            existing_user = db.GqlQuery("select * from User where username = :1",username)
            logging.debug(existing_user.get())
            if existing_user.get():
                params['user_exist'] = "That user already exists."
                self.render('signup.html', **params)
            else:
                password_salted = make_pw_hash(username,password)
                user = User(username = username, password = password_salted, email = email)
                user.put()
                #time.sleep(3)
                user_id = user.key().id()
                encrypted = make_secure_val(str(user_id))
                self.response.headers.add_header('Set-Cookie', 'name=%s; Path=/'%str(encrypted))
                self.redirect('/welcome')#+ username)



        

app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/blog/newpost', NewPost),
    ('/blog/signup', Signup),
    ('/blog', MainHandler),
    ('/welcome', MainHandler),
    ('/blog/(\d+)', Permalink),
    ('/signup', Signup)
], debug=True)

                                   
                                   
                                   
