#!/bin/bash
#@ECHO off
#SETLOCAL

dotnet restore

dotnet build --no-restore --configuration Release

dotnet test --no-build --configuration Release
