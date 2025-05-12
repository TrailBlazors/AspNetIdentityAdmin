using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Linq;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Security.Claims;

namespace AspNetIdentityAdmin.Controllers
{
    [Authorize(Roles = "Admin")]
    public class AdminController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public AdminController(UserManager<IdentityUser> userManager,
                               RoleManager<IdentityRole> roleManager)
        {
            _userManager = userManager;
            _roleManager = roleManager;
        }

        // GET: Admin landing page
        public IActionResult Index()
        {
            return View();
        }

        // List all users
        public IActionResult Users()
        {
            var users = _userManager.Users.ToList();
            return View(users);
        }

        // GET: Edit a user
        public async Task<IActionResult> EditUser(string id)
        {
            if (string.IsNullOrEmpty(id))
                return NotFound();

            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
                return NotFound();

            return View(user);
        }

        // POST: Edit a user
        [HttpPost]
        public async Task<IActionResult> EditUser(string id, IdentityUser updatedUser)
        {
            if (id != updatedUser.Id)
                return BadRequest();

            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
                return NotFound();

            // Update user properties as needed
            user.UserName = updatedUser.UserName;
            user.Email = updatedUser.Email;
            // ...update additional properties...

            var result = await _userManager.UpdateAsync(user);
            if (result.Succeeded)
                return RedirectToAction(nameof(Users));

            foreach (var error in result.Errors)
                ModelState.AddModelError("", error.Description);

            return View(updatedUser);
        }

        // POST: Delete a user
        [HttpPost]
        public async Task<IActionResult> DeleteUser(string id)
        {
            if (string.IsNullOrEmpty(id))
                return NotFound();

            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
                return NotFound();

            await _userManager.DeleteAsync(user);
            return RedirectToAction(nameof(Users));
        }

        // List all roles
        public IActionResult Roles()
        {
            var roles = _roleManager.Roles.ToList();
            return View(roles);
        }

        // GET: Create a new role
        public IActionResult CreateRole()
        {
            return View();
        }

        // POST: Create a new role
        [HttpPost]
        public async Task<IActionResult> CreateRole(string roleName)
        {
            if (string.IsNullOrWhiteSpace(roleName))
            {
                ModelState.AddModelError("", "Role name is required.");
                return View();
            }

            var result = await _roleManager.CreateAsync(new IdentityRole(roleName));
            if (result.Succeeded)
                return RedirectToAction(nameof(Roles));

            foreach (var error in result.Errors)
                ModelState.AddModelError("", error.Description);

            return View();
        }

        // GET: Edit a role
        public async Task<IActionResult> EditRole(string id)
        {
            if (string.IsNullOrEmpty(id))
                return NotFound();

            var role = await _roleManager.FindByIdAsync(id);
            if (role == null)
                return NotFound();

            return View(role);
        }

        // POST: Edit a role
        [HttpPost]
        public async Task<IActionResult> EditRole(string id, string roleName)
        {
            if (string.IsNullOrWhiteSpace(roleName))
            {
                ModelState.AddModelError("", "Role name is required.");
                return View();
            }

            var role = await _roleManager.FindByIdAsync(id);
            if (role == null)
                return NotFound();

            role.Name = roleName;
            var result = await _roleManager.UpdateAsync(role);
            if (result.Succeeded)
                return RedirectToAction(nameof(Roles));

            foreach (var error in result.Errors)
                ModelState.AddModelError("", error.Description);

            return View(role);
        }

        // POST: Delete a role
        [HttpPost]
        public async Task<IActionResult> DeleteRole(string id)
        {
            if (string.IsNullOrEmpty(id))
                return NotFound();

            var role = await _roleManager.FindByIdAsync(id);
            if (role == null)
                return NotFound();

            await _roleManager.DeleteAsync(role);
            return RedirectToAction(nameof(Roles));
        }

        // GET: Manage roles for a user
        public async Task<IActionResult> ManageUserRoles(string userId)
        {
            if (string.IsNullOrEmpty(userId))
                return NotFound();

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return NotFound();

            var model = new ManageUserRolesViewModel
            {
                UserId = userId,
                UserName = user.UserName,
                Roles = _roleManager.Roles.Select(r => new RoleSelection
                {
                    RoleId = r.Id,
                    RoleName = r.Name,
                    Selected = _userManager.IsInRoleAsync(user, r.Name).Result
                }).ToList()
            };

            return View(model);
        }

        // POST: Manage roles for a user
        [HttpPost]
        public async Task<IActionResult> ManageUserRoles(ManageUserRolesViewModel model)
        {
            var user = await _userManager.FindByIdAsync(model.UserId);
            if (user == null)
                return NotFound();

            var userRoles = await _userManager.GetRolesAsync(user);
            var selectedRoles = model.Roles.Where(r => r.Selected).Select(r => r.RoleName).ToList();

            // Add roles that are selected but not already assigned
            var addResult = await _userManager.AddToRolesAsync(user, selectedRoles.Except(userRoles));
            if (!addResult.Succeeded)
            {
                ModelState.AddModelError("", "Failed to add selected roles.");
                return View(model);
            }

            // Remove roles that are unselected but currently assigned
            var removeResult = await _userManager.RemoveFromRolesAsync(user, userRoles.Except(selectedRoles));
            if (!removeResult.Succeeded)
            {
                ModelState.AddModelError("", "Failed to remove unselected roles.");
                return View(model);
            }

            return RedirectToAction(nameof(Users));
        }

        // GET: Manage claims for a user
        public async Task<IActionResult> ManageUserClaims(string userId)
        {
            if (string.IsNullOrEmpty(userId))
                return NotFound();

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return NotFound();

            var existingClaims = await _userManager.GetClaimsAsync(user);
            var model = new ManageUserClaimsViewModel
            {
                UserId = userId,
                UserName = user.UserName,
                Claims = existingClaims.Select(c => new ClaimSelection { Type = c.Type, Value = c.Value, Selected = true }).ToList()
            };

            // Optionally, you could add additional claims for selection
            return View(model);
        }

        // POST: Manage claims for a user
        [HttpPost]
        public async Task<IActionResult> ManageUserClaims(ManageUserClaimsViewModel model)
        {
            var user = await _userManager.FindByIdAsync(model.UserId);
            if (user == null)
                return NotFound();

            var currentClaims = await _userManager.GetClaimsAsync(user);
            var selectedClaims = model.Claims.Where(c => c.Selected)
                                             .Select(c => new Claim(c.Type, c.Value))
                                             .ToList();
            // Remove claims that are not selected
            var removeClaims = currentClaims.Where(c => !selectedClaims.Any(sc => sc.Type == c.Type && sc.Value == c.Value)).ToList();
            if (removeClaims.Any())
            {
                var removeResult = await _userManager.RemoveClaimsAsync(user, removeClaims);
                if (!removeResult.Succeeded)
                {
                    ModelState.AddModelError("", "Failed to remove claims.");
                    return View(model);
                }
            }
            // Add new claims that the user does not have
            var addClaims = selectedClaims.Where(sc => !currentClaims.Any(c => c.Type == sc.Type && c.Value == sc.Value)).ToList();
            if (addClaims.Any())
            {
                var addResult = await _userManager.AddClaimsAsync(user, addClaims);
                if (!addResult.Succeeded)
                {
                    ModelState.AddModelError("", "Failed to add claims.");
                    return View(model);
                }
            }

            return RedirectToAction(nameof(Users));
        }
    }

    // ViewModels for managing roles and claims

    public class ManageUserRolesViewModel
    {
        public string UserId { get; set; }
        public string UserName { get; set; }
        public List<RoleSelection> Roles { get; set; }
    }

    public class RoleSelection
    {
        public string RoleId { get; set; }
        public string RoleName { get; set; }
        public bool Selected { get; set; }
    }

    public class ManageUserClaimsViewModel
    {
        public string UserId { get; set; }
        public string UserName { get; set; }
        public List<ClaimSelection> Claims { get; set; }
    }

    public class ClaimSelection
    {
        public string Type { get; set; }
        public string Value { get; set; }
        public bool Selected { get; set; }
    }
}