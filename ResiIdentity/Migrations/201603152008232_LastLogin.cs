namespace ResiIdentity.Migrations
{
    using System;
    using System.Data.Entity.Migrations;
    
    public partial class LastLogin : DbMigration
    {
        public override void Up()
        {
            AddColumn("dbo.AspNetUsers", "LastLogin", c => c.String());
        }
        
        public override void Down()
        {
            DropColumn("dbo.AspNetUsers", "LastLogin");
        }
    }
}
