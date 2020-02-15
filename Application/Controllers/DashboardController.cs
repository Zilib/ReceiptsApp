using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Application.Areas.Identity.Data;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace Application.Controllers
{
    public class DashboardController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;

        public DashboardController(UserManager<ApplicationUser> userManager)
        {
            _userManager = userManager;
        }

        [Authorize]
        public async Task<IActionResult> Index()
        {
            // Load user to data
            ApplicationUser applicationUser = await _userManager.GetUserAsync(User);
            
            if(applicationUser.Surname == null ||
                applicationUser.Name == null)
            {
                return RedirectToAction("SetDetails", "Account");
            }

            return View();
        }
    }
}