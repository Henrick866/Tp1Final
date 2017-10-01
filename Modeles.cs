using Microsoft.EntityFrameworkCore;
using System.Collections.Generic;

namespace Tp1Secu
{
    public class DatabaseContext : DbContext
    {
        public DbSet<User> Users { get; set; }
        public DbSet<Pass> Passwords { get; set; }

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            optionsBuilder.UseSqlite("Data Source=DbTp1.db");
        }
    }

    public class User
    {
        public int UserId { get; set; }
        public string UserName { get; set; }
        public string UserPassword { get; set; } //Master_PW, crypté SHA256(PW+SALT)
        public string UserSalt { get; set; } //Sel, 
    }

    public class Pass{
        public int PassId { get; set; }
        public string PassTag { get; set; } //identifier le pass
        public string Password { get; set; } 
        public string PassKey { get; set; }
    }
}