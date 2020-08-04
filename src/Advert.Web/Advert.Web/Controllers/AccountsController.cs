using Advert.Web.Models.Accounts;
using Amazon.AspNetCore.Identity.Cognito;
using Amazon.Extensions.CognitoAuthentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Collections;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Advert.Web.Controllers
{
    public class AccountsController : Controller
    {
        private readonly SignInManager<CognitoUser> signInManager;
        private readonly CognitoUserPool userPool;
        private readonly UserManager<CognitoUser> userManager;

        public AccountsController(SignInManager<CognitoUser> signInManager, CognitoUserPool userPool, UserManager<CognitoUser> userManager)
        {
            this.signInManager = signInManager ?? throw new System.ArgumentNullException(nameof(signInManager));
            this.userPool = userPool ?? throw new System.ArgumentNullException(nameof(userPool));
            this.userManager = userManager ?? throw new System.ArgumentNullException(nameof(userManager));
        }

        public IActionResult Login(LoginModel model)
        {
            return View(model);
        }

        [HttpPost]
        [ActionName("Login")]
        public async Task<IActionResult> LoginPost(LoginModel model)
        {
            if (ModelState.IsValid)
            {
                var result = await signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, false);
                if (result.Succeeded)
                    return RedirectToAction("Index","Home");
                else
                    ModelState.AddModelError("LoginError", "Email and password does not match.");
            }
            return View(model);
        }


        public IActionResult Signup()
        {
            return View(new SignupModel());
        }

        [HttpPost]
        public async Task<IActionResult> Signup(SignupModel model)
        {
            if (ModelState.IsValid)
            {
                var user = userPool.GetUser(model.Email);
                if (user.Status != null)
                {
                    ModelState.AddModelError("UserExists", "User with this email already exists.");
                    return View(model);
                }
                user.Attributes.Add(CognitoAttribute.Name.AttributeName, model.Email);

                var createdUser = await userManager.CreateAsync(user, model.Password);
                if (createdUser.Succeeded)
                {
                    return RedirectToAction("Confirm");
                }
                AddModelErrors(createdUser.Errors);
            }
            return View(model);
        }

        public IActionResult Confirm()
        {
            return View(new ConfirmModel());
        }

        [HttpPost]
        public async Task<IActionResult> Confirm(ConfirmModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await userPool.FindByIdAsync(model.Email);
                if (user == null)
                {
                    ModelState.AddModelError("NotFoun", "A user with this email was not found.");
                    return View(model);
                }

                var confirmation = await (userManager as CognitoUserManager<CognitoUser>).ConfirmSignUpAsync(user, model.Code, true);
                if (confirmation.Succeeded)
                {
                    return RedirectToAction("Index", "Home");
                }

                AddModelErrors(confirmation.Errors);

            }
            return View(model);
        }

        private void AddModelErrors(IEnumerable<IdentityError> errors)
        {
            foreach (var error in errors)
            {
                ModelState.AddModelError(error.Code, error.Description);
            }
        }
    }
}
