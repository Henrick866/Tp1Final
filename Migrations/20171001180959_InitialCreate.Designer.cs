﻿// <auto-generated />
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.EntityFrameworkCore.Storage;
using System;
using Tp1Secu;

namespace Tp1Secu.Migrations
{
    [DbContext(typeof(DatabaseContext))]
    [Migration("20171001180959_InitialCreate")]
    partial class InitialCreate
    {
        protected override void BuildTargetModel(ModelBuilder modelBuilder)
        {
#pragma warning disable 612, 618
            modelBuilder
                .HasAnnotation("ProductVersion", "2.0.0-rtm-26452");

            modelBuilder.Entity("Tp1Secu.Pass", b =>
                {
                    b.Property<int>("PassId")
                        .ValueGeneratedOnAdd();

                    b.Property<string>("PassKey");

                    b.Property<string>("PassTag");

                    b.Property<string>("Password");

                    b.HasKey("PassId");

                    b.ToTable("Passwords");
                });

            modelBuilder.Entity("Tp1Secu.User", b =>
                {
                    b.Property<int>("UserId")
                        .ValueGeneratedOnAdd();

                    b.Property<string>("UserName");

                    b.Property<string>("UserPassword");

                    b.Property<string>("UserSalt");

                    b.HasKey("UserId");

                    b.ToTable("Users");
                });
#pragma warning restore 612, 618
        }
    }
}
